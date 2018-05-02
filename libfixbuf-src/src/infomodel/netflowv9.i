static fbInfoElement_t infomodel_array_static_netflowv9[] = {
    FB_IE_INIT_FULL("NF_F_FW_EXT_EVENT", 0, 9997, 2, FB_IE_IDENTIFIER | FB_IE_F_ENDIAN, 0, 0, FB_UINT_16, NULL),
    FB_IE_INIT_FULL("NF_F_FW_EVENT", 0, 9998, 1, FB_IE_IDENTIFIER, 0, 0, FB_UINT_8, NULL),
    FB_IE_INIT_FULL("ciscoNetflowGeneric", 0, 9999, 8, FB_IE_QUANTITY | FB_IE_F_ENDIAN, 0, 0, FB_UINT_64, NULL),

    FB_IE_NULL
};
