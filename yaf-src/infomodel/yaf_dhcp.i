static fbInfoElement_t infomodel_array_static_yaf_dhcp[] = {
    FB_IE_INIT_FULL("dhcpFingerPrint", 6871, 242, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("dhcpVendorCode", 6871, 243, FB_IE_VARLEN, FB_IE_DEFAULT | FB_IE_F_REVERSIBLE, 0, 0, FB_STRING, NULL),
    FB_IE_INIT_FULL("dhcpOption", 6871, 297, 1, FB_IE_QUANTITY, 0, 0, FB_UINT_8, NULL),

    FB_IE_NULL
};
