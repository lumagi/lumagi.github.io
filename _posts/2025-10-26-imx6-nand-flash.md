---
title:  "Decoding raw i.MX6 NAND flash images"
date:   2025-10-26 18:21:00 +0100
categories: [Embedded]
tags: [NAND, Flash, i.MX6, BCH]
math: true
---

I was recently working with a PCB featuring an i.MX6 SoC and a raw NAND flash chip. The SoC was running a u-boot and an embedded Linux off of the NAND flash chip. Since the debug port was properly locked, I wanted to take a look at the embedded u-boot and Linux. I decided to desolder and dump the flash chip. This post documents how the i.MX6 stores user data on an external NAND flash and how this user data can be manually extracted while correcting bit errors.

## NAND Flash Memory

The NAND flash memory I was working with supported the [ONFI specification 1.0](https://onfi.org/files/onfi_1_0_gold.pdf). I followed [the post by Colin O'Flynn](https://colinoflynn.com/2024/04/dumping-parallel-nand-with-glasgow/) to solder wires to the BGA pads of the NAND flash. I used enameled wires and taped down each row after the other. I only soldered a single VCC and VDD pad, which turned out to be okay. All in all, I soldered the following connections:

| Pin Type       | Description                            |
| -------------- | -------------------------------------- |
| VCC            | 3V power, I only soldered a single pad |
| VDD            | Ground, I only soldered a single pad   |
| IO0 - IO7      | 8 bit I/O lines                        |
| CE#            | Chip Enable (Active Low)               |
| RE#            | Read Enable (Active Low)               |
| WE#            | Write Enable (Active Low)              |
| CLE            | Command Latch Enable                   |
| ALE            | Address Latch Enable                   |
| WP#            | Write Protect (Active Low)             |
| R/B#           | Busy signal from NAND, Open Drain      |

The `R/B#` signal requires a dedicated pull-up resistor since it is an open-drain signal. I didn't solder the protection pin since the NAND flash has an internal pull-down resistor. The resistor unprotects the chip by default.

I used the ONFI applet of the [Glasgow Interface Explorer](https://glasgow-embedded.org/) to communicate with the NAND flash. It was very impressive to see the ONFI applet work its magic right out of the box. Conveniently, the Glasgow applet directly dumped the flash characteristics contained in the Parameter Page (see chapter 5.4.1 of the ONFI specificaiton).


### Flash Parameters
The flash memory had the following characteristics:

| Parameter                          | Value     |
| ---------------------------------- | --------- |
| Bytes per page                     | 2048      |
| Spare bytes per page               | 64        |
| Pages per erase block              | 64        |
| Number of logical units            | 1         |
| Number of block ins a logical unit | 4096      |
| Number of bits ECC correctability  | 4         |

The last parameter defines the required ECC strength. According to the specification, the host or flash controller must be able to identify and correct this many bit errors per 512 byte of user data. In our case, the ECC must be strong enough to identify and correct up to four bit flips per 512 byte of data. The specification does not say what ECC mechanism must be used or how this data should be organized within a flash page.

To me, this was unexpected. Literature or Wikipedia mention the spare area to be specific for ECC or manufacturing information. I simply assumed that this ECC information must then go into the spare area since that was its purpose, right? It turned out that at least in my case, there was no logical distinction between the two. According to the flash memory documentation, flash pages are always written or dumped with the full 2112 bytes.
The flash memory page has this extra capacity for correction information, but how or where this information is stored within the page is of no interest to the flash memory. It provides this extra data per page as a convenience to the host, which must define its purpose.

In my scenario, the i.MX6 was acting as the host or flash controller. It also handled the page as a contiguous region of memory.

### Dumping the flash


The Glasgow applet worked right out of the box, and I was able to dump the memory successfully. The applet offers you the option of separating the regular area and spare area of the flash pages into separate files. Although this first sounded like a good idea, I later noticed that the flash controller did not make any distinction between the two. It treated the flash page as a contiguous region of 2112 bytes, so dumping them interleaved was the right choice.

As Colin described in his blog, I dumped the memory multiple times to work out any potential bit flips by means of majority voting. I expected my soldered enameled wires to introduce quite a bit of noise and transmission errors. And indeed, after dumping the memory twice and comparing the two dumps, I noticed a few bit errors. Compared to the size of the memory, there were only few, but they were present.
Since I first assumed these bit errors to have been caused by interference, I pulled more dumps and wrote a little Python script to work out the errors by means of majority voting. However, the bit errors always occurred at the same locations in the dump and had a rather constant probability of occurring. Sometimes, this probability was almost 50/50, so there was no way to determine the proper value of a bit by pulling more dumps. And even if the bit was more likely to flip one way, there was no easy way of knowing if that was the correct value. In summary, it looked like these bit flips were not produced by the solder setup but by actual errors in the NAND flash chip.

To better understand the contents of the dump, I ran binwalk across the file. It looked like large portions of the dump were compressed or even encrypted. Under these circumstances, even a single bit error could prevent a successful decoding. I needed to better understand the format of the flash contents and potentially correct bit errors to be able to successfully extract the data.

## Flash Controller

In comparison to NOR flash memory, a NAND flash memory requires more intensive care to be working reliably. This is most notably the handling of bad blocks and the transparent application of ECC to detect and correct bit flips in the data. As I was already able to experience while dumping the data from the memory, bit flips do occur during regular operation and need to be handled.

In my case, it was the job of the i.MX6 to take care of these tasks. The i.MX6 features a General Purpose Media Interface (GPMI) that operates as a flash controller. The GPMI uses the BCH accelerator of the chip to implement error correcting codes. The following sections of the reference manual are of interest (the manual can be found with a Google search):

* Chapter 17: 40-Bit Correcting ECC Accelerator (BCH)
    * 17.2.2: Flash Page Layout
    * 17.6.8: Hardware BCH ECC Flash 0 Layout 0 Register
    * 17.6.9: Hardware BCH ECC Flash 0 Layout 1 Register
* Chapter 8: System Boot
    * 8.5.2.5: Back block handling in ROM
    * 8.5.2.8: Typical NAND Page Organization

The flash controller provides a convenient error-free abstraction of the raw flash memory. It does so by multiplexing the user data with additionall error-correcting information and metadata.

### Flash Layout

The flash controller supports different flash page layouts depending on the page size and the ECC needs of the flash chip. In general, the complete flash page (regular and spare area) is divided into blocks. In my case, the user data on the page was split into four block of 512 byte. After each data block comes an ECC block that carries the correcting code for the preceding data block. Before the first block comes a block of metadata. This metadata is specific to the i.MX flash controller. In contrast to `ECC1` to `ECCN`, `ECC0` also covers the metadata block.

The following image shows the general layout of a flash page:

![Flash Layout](/assets/images/2025_11_imx_flash_page.svg){: width="100%"}

The size of the metadata, the size of the blocks, and the applied BCH strength are configurable (see the mentioned registers above). My first assumption was that the configuration of these registers is done statically by u-boot during boot. I poked around in the u-boot code for a little while until I found the relevant sections.

### u-boot i.MX Flash Configuration

I was surprised to see that the configuration of the i.MX6 flash controller in u-boot is not done statically in the sense that a fixed static configuration is applied. Instead, the controller is dynamically configured depending on the characteristics of the chip. When booting, u-boot automatically configures the flash controller according to these flash parameters. The flash parameters are read from the flash chip and stored in [struct nand_chip](https://github.com/u-boot/u-boot/blob/56cac250b0839ddbad1311d3ca4231f532b5aadf/include/linux/mtd/rawnand.h#L914). The two most important values are `ecc_strength_ds` and `ecc_step_ds`, which are the required ECC strength and the number of bytes after which an ECC is required. As mentioned above, in my case this was 4 bits of ECC correctability per 512 byte of data.

The main function responsible for determining the configuration is called [mxs_nand_set_geometry](https://github.com/u-boot/u-boot/blob/56cac250b0839ddbad1311d3ca4231f532b5aadf/drivers/mtd/nand/raw/mxs_nand.c#L1125). Based on the known characteristics of the flash chip, I concluded that it branches to [mxs_nand_legacy_calc_ecc_layout](https://github.com/u-boot/u-boot/blob/56cac250b0839ddbad1311d3ca4231f532b5aadf/drivers/mtd/nand/raw/mxs_nand.c#L197) for calculation of the ECC parameters. An extract of `mxs_nand_legacy_calc_ecc_layout` is shown below:

```c
static inline int mxs_nand_legacy_calc_ecc_layout(struct bch_geometry *geo,
					   struct mtd_info *mtd)
{
    <...>
    /* The default for the length of Galois Field. */
    geo->gf_len = 13;

    /* The default for chunk size. */
    geo->ecc_chunk0_size = 512;
    geo->ecc_chunkn_size = 512;

    <...>

    geo->ecc_chunk_count = mtd->writesize / geo->ecc_chunkn_size;

    /*
     * Determine the ECC layout with the formula:
     *	ECC bits per chunk = (total page spare data bits) /
     *		(bits per ECC level) / (chunks per page)
     * where:
     *	total page spare data bits =
     *		(page oob size - meta data size) * (bits per byte)
     */
    geo->ecc_strength = ((mtd->oobsize - MXS_NAND_METADATA_SIZE) * 8)
            / (geo->gf_len * geo->ecc_chunk_count);

    geo->ecc_strength = min(round_down(geo->ecc_strength, 2),
                nand_info->max_ecc_strength_supported);

    <...>
}
```

The function configures a block size of 512 bytes and Galois Field `GF(13)` for the BCH codes. The i.MX metadata field is always set to a length of `MXS_NAND_METADATA_SIZE = 10` bytes. With a flash page size of $2048 + 64 = 2112$, the code comes to the conclusion that four blocks fit into a page, meaning that `geo->ecc_chunk_count` is four.
The only remaining unknown is the length of each `ECC` field. Instead of directly using what is required according to the flash parameters, the function determines which ECC strength is theoretically achievable based on the available space: the configuration stores four blocks of 512 byte in the page, which completely fills the regular page area. Out of the 64 byte of spare area only 54 byte can be used for ECC since we must account for the 10 byte of metadata. Consequently, each of the four blocks can be protected with 13 bytes of ECC.
Since we're using Galois field `GF(2^13)`, each bit of correctability requires 13 bits of redundancy. In this specific case, $13 \cdot 8 / 13 = 8$ bits of correctability are at maximum possible based on the available space.

After calculating the maximum possible ECC strength, the function checks if this strength satisfies the requirements mentioned in the flash parameter page. Here, the calculated correctability of 8 exceeds the requirement of 4 and is accepted by the function. Hence, we have the following parameters for the flash page protection:

| Parameter                          | Value     |
| ---------------------------------- | --------- |
| Block size                         | 512 byte  |
| Metadata size                      | 10 byte   |
| BCH Galois Field                   | 13        |
| BCH level                          | BCH8      |
| ECC size per block                 | 13 byte   |

If we fully calculate this through, we have $4 \cdot 512 + 4 \cdot 13 + 10 = 2110$ bytes required, which means that the two last bytes in the flash page are unused.

## Flash Dump Data Reconstruction in Python

Now that the flash page layout was known, the last step was to make use of the ECC fields in the flash pages to correct the bit errors in the dump. This basically meant reimplementing the ECC correction algorithm. After doing a bit of testing, I found that the following steps needed to be implemented:

* Using the BCH ECC to correct bit errors in the blocks of each page.
* Swapping the bad block marker from address 0x800 back to page address 0x0.
* Stripping the $4 \cdot 13$ bytes of ECC and the two spare bytes at the end of the page to retrieve 2048 byte of user data.

### Bit correction with BCH

This task is a brilliant example of why I love Python as a tooling language: there already exists a neat Python library called [python-bchlib](https://github.com/jkent/python-bchlib) that implements the BCH algorithm.

The following code snippet performs the ECC correction in place. A bytearray containing a single flash page is passed into the function and modified in place.

```python
from bchlib import BCH

USER_PAGE_LEN = 2048
PAGE_LEN = USER_PAGE_LEN + 64
META_LEN = 10
BLOCK_LEN = 512
ECC_LEN = 13
EMPTY_ECC = b"\xff" * ECC_LEN

def run_page_ecc_in_place(page: bytearray) -> None:
    if len(page) != PAGE_LEN:
        raise ValueError(
            f"Supplied page data does not have required length: {PAGE_LEN}"
        )

    bch = BCH(8, m=13, swap_bits=True)

    offset = 0
    for block_index in range(4):
        if block_index == 0:
            block_len = BLOCK_LEN + META_LEN
        else:
            block_len = BLOCK_LEN

        block_w_ecc = page[offset : offset + block_len + ECC_LEN]
        block_data = block_w_ecc[:block_len]
        block_ecc = block_w_ecc[block_len:]

        expected_ecc = bch.encode(block_data)
        if block_ecc != EMPTY_ECC and block_ecc != expected_ecc:
            # The correction is done in place
            bch.correct(block_data, block_ecc)

        offset += len(block_w_ecc)

```

### Bad Block Marker Swapping

After correcting the bit errors, I noticed that the dump data still contained spurious 0xFF bytes in an otherwise completely empty flash page. These bytes were always located at offset 0x800. Chapter 8.5.2.5 explains that the single byte at this offset is the original bad block marker written there by the flash manufacturer.
The motivation for this behavior is also documented in a [legacy document by freescale](https://community.nxp.com/pwmxy87654/attachments/pwmxy87654/imx-processors/134096/2/AN_MX_NAND_BAD_BLOCK.pdf). Due to the interleaved approach of putting the ECC in between the 512 byte data blocks, the bad block marker at offset 0x800 would be located inside the last data block. To avoid this, the flash controller stores the marker in the metadata field which is kept at the beginning of the page. However, when the page is written to the NAND flash, the bad block marker byte is again swapped back to 0x800 to maintain its original position. The data byte contained at offset 0x800 is placed at offset 0x0. The swapping occurs before the ECC for the page blocks is calculated.

We must invert this operation when we manually decode the page. Since, during a write, the ECC is applied after the swap, we must first correct the ECC and then swap back.

```python
BB_MARKER_OFFSET = 0x800


def swap_bb_marker_in_place(page: bytearray) -> None:
    tmp = page[0]
    page[0] = page[BB_MARKER_OFFSET]
    page[BB_MARKER_OFFSET] = tmp
```

### Stripping the metadata and ECC

The last step is to strip the unneeded metadata and ECC information to retrieve the 2048 byte of user data stored in the page:

```python
def strip_meta_and_ecc(src: bytes | bytearray) -> bytearray:
    if len(src) != PAGE_LEN:
        raise ValueError(
            f"Supplied page data does not have required length: {PAGE_LEN}"
        )

    src_wo_meta = src[META_LEN:]
    dst = bytearray(USER_PAGE_LEN)

    for blk_idx in range(4):
        src_start = blk_idx * (BLOCK_LEN + ECC_LEN)
        data_block = src_wo_meta[src_start : src_start + BLOCK_LEN]

        dst_start = blk_idx * BLOCK_LEN
        dst[dst_start : dst_start + BLOCK_LEN] = data_block

    return dst
```

## Conclusion

With the code snippets above, I was able to fully recover the data and correct any bit errors. I was even able to decompress the compressed portion of the stored data without any issues.

It was very interesting to see and understand how the data is physically stored and protected in a NAND flash chip. I hope this information can be helpful to others that must go through the same process. Although NXP partially documents its implementation in the reference manual, there is no public implementation of the algorithm. And since all the mechanisms mentioned here are solely applied in hardware, there is no easy way to reverse engineer the implementation.
