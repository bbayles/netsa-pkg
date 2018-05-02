<?xml version='1.0' encoding='UTF-8'?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:iana="http://www.iana.org/assignments"
                xmlns:cert="http://www.cert.org/ipfix">
  <xsl:output method="text"/>

  <xsl:strip-space elements="*"/>

  <!-- The name of the array fbInfoElement_t array  -->
  <xsl:param name="array-name">defaults</xsl:param>

  <!-- A pipe-delimited list of groups to output.  Empty implies all
       groups -->
  <xsl:param name="target-groups"/>

  <!-- A list of IE numbers that should not be considered reversible -->
  <xsl:variable name="non-reversible-ie-ids">|148|145|149|137|210|239|</xsl:variable>
  
  <!-- A list if IE groups that should not be considered reversible -->
  <xsl:variable name="non-reversible-ie-groups">|config|processCounter|netflow v9|</xsl:variable>

  <!-- Ensure there are pipes on all ends -->
  <xsl:variable name="tgroup" select="concat('|', $target-groups, '|')"/>

  <xsl:template match="/">
    <xsl:text>static fbInfoElement_t </xsl:text>
    <xsl:value-of select="$array-name"/>
    <xsl:text>[] = {&#10;</xsl:text>
    <xsl:for-each select="//iana:record[iana:dataType]">
      <xsl:if test="not($target-groups) or 
                    (iana:group and contains($tgroup, 
                    concat('|', iana:group, '|')))">

        <xsl:text>    FB_IE_INIT_FULL("</xsl:text>

        <!-- name -->
        <xsl:value-of select="normalize-space(iana:name)"/>
        <xsl:text>", </xsl:text>

        <!-- enterprise id -->
        <xsl:choose>
          <xsl:when test="cert:enterpriseId">
            <xsl:value-of select="cert:enterpriseId"/>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>0</xsl:text>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text>, </xsl:text>

        <!-- element id -->
        <xsl:value-of select="iana:elementId"/>
        <xsl:text>, </xsl:text>

        <!-- length -->
        <xsl:choose>
          <xsl:when test="iana:dataType = 'unsigned8' or iana:dataType
                          = 'signed8' or iana:dataType = 'boolean'">
            <xsl:text>1</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned16' or iana:dataType =
                          'signed16'">
            <xsl:text>2</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned32' or iana:dataType =
                          'signed32' or iana:dataType = 'dateTimeSeconds' or
                          iana:dataType = 'ipv4Address' or iana:dataType =
                          'float32'">
            <xsl:text>4</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'macAddress'">
            <xsl:text>6</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned64' or iana:dataType =
                          'signed64' or iana:dataType = 'float64' or
                          iana:dataType = 'dateTimeMilliseconds' or 
                          iana:dataType = 'dateTimeMicroseconds' or
                          iana:dataType = 'dateTimeNanoseconds'">
            <xsl:text>8</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'ipv6Address'">
            <xsl:text>16</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'octetArray' or
                          iana:dataType = 'string' or iana:dataType
                          = 'basicList' or iana:dataType =
                          'subTemplateList' or iana:dataType =
                          'subTemplateMultiList'">
            <xsl:text>FB_IE_VARLEN</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>&#10;#error Unknown dataType "</xsl:text>
            <xsl:value-of select="iana:dataType"/>
            <xsl:text>"&#10;</xsl:text>
          </xsl:otherwise>
        </xsl:choose>
        <xsl:text>, </xsl:text>

        <!-- ** flags ** -->
        <!-- semantics -->
        <xsl:choose>
          <xsl:when test="not(iana:dataTypeSemantics)">
            <xsl:choose>
              <!-- RFC 7012, 3.2.1 : Quantity is the default semantic
                   of all numeric data types -->
              <xsl:when test="substring(iana:dataType, 1, 6) = 'signed' or
                              substring(iana:dataType, 1, 8) = 'unsigned' or
                              substring(iana:dataType, 1, 8) = 'float'">
                <xsl:text>FB_IE_QUANTITY</xsl:text>
              </xsl:when>
              <xsl:otherwise>
                <xsl:text>FB_IE_DEFAULT</xsl:text>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'default'">
            <xsl:text>FB_IE_DEFAULT</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'quantity'">
            <xsl:text>FB_IE_QUANTITY</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'totalCounter'">
            <xsl:text>FB_IE_TOTALCOUNTER</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'deltaCounter'">
            <xsl:text>FB_IE_DELTACOUNTER</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'identifier'">
            <xsl:text>FB_IE_IDENTIFIER</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'flags'">
            <xsl:text>FB_IE_FLAGS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'list'">
            <xsl:text>FB_IE_LIST</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'snmpCounter'">
            <xsl:text>FB_IE_SNMPCOUNTER</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataTypeSemantics = 'snmpGauge'">
            <xsl:text>FB_IE_SNMPGAUGE</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>&#10;#error Unknown dataTypeSemantics "</xsl:text>
            <xsl:value-of select="iana:dataTypeSemantics"/>
            <xsl:text>"&#10;</xsl:text>
          </xsl:otherwise>
        </xsl:choose>

        <!-- units -->
        <xsl:choose>
          <xsl:when test="not(iana:units)"/>
          <xsl:when test="iana:units = 'none'"/>
          <xsl:when test="iana:units = 'bits'">
            <xsl:text> | FB_UNITS_BITS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'octets'">
            <xsl:text> | FB_UNITS_OCTETS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'packets'">
            <xsl:text> | FB_UNITS_PACKETS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'flows'">
            <xsl:text> | FB_UNITS_FLOWS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'seconds'">
            <xsl:text> | FB_UNITS_SECONDS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'milliseconds'">
            <xsl:text> | FB_UNITS_MILLISECONDS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'microseconds'">
            <xsl:text> | FB_UNITS_MICROSECONDS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'nanoseconds'">
            <xsl:text> | FB_UNITS_NANOSECONDS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = '4-octet words'">
            <xsl:text> | FB_UNITS_WORDS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = '4 octets'">
            <!-- Erroneously used in the iana ipfix xml file -->
            <xsl:text> | FB_UNITS_WORDS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'messages'">
            <xsl:text> | FB_UNITS_MESSAGES</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'hops'">
            <xsl:text> | FB_UNITS_HOPS</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'entries'">
            <xsl:text> | FB_UNITS_ENTRIES</xsl:text>
          </xsl:when>
          <xsl:when test="iana:units = 'frames'">
            <xsl:text> | FB_UNITS_FRAMES</xsl:text>
          </xsl:when>
          <!-- Ignore illegal units for now, as there are several in the
               iana ipfix xml file -->
          <!-- <xsl:otherwise> -->
          <!--   <xsl:text>&#10;#error Unknown units "</xsl:text> -->
          <!--   <xsl:value-of select="iana:units"/> -->
          <!--   <xsl:text>"&#10;</xsl:text> -->
          <!-- </xsl:otherwise> -->
        </xsl:choose>

        <!-- endian -->
        <xsl:if test="iana:dataType != 'unsigned8' and
                      iana:dataType != 'signed8' and
                      (iana:dataType = 'ipv4Address' or
                       starts-with(iana:dataType, 'unsigned') or
                       starts-with(iana:dataType, 'signed') or
                       starts-with(iana:dataType, 'float') or
                       starts-with(iana:dataType, 'dateTime'))">
          <xsl:text> | FB_IE_F_ENDIAN</xsl:text>
        </xsl:if>

        <!-- reversible -->
        <xsl:choose>
          <!-- Reversible if marked as such -->
          <xsl:when test="cert:reversible">
            <xsl:if test="cert:reversible = '1' or cert:reversible = 'true'">
              <xsl:text> | FB_IE_F_REVERSIBLE</xsl:text>
            </xsl:if>
          </xsl:when>
          <!-- Break out if PEN is set -->
          <xsl:when test="cert:enterpriseId"/>
          <!-- Break out if group is in non-reversible-ie-groups -->
          <xsl:when test="contains($non-reversible-ie-groups, concat('|',
                          iana:group, '|'))"/>
          <!-- Break out if ID is in non-reversible-ie-ids -->
          <xsl:when test="contains($non-reversible-ie-ids, concat('|',
                          iana:elementId, '|'))"/>
          <xsl:otherwise>
            <xsl:text> | FB_IE_F_REVERSIBLE</xsl:text>
          </xsl:otherwise>
        </xsl:choose>

        <!-- range -->
        <xsl:text>, </xsl:text>
        <xsl:choose>
          <xsl:when test="not(iana:range)"><xsl:text>0, 0</xsl:text></xsl:when>
          <xsl:otherwise>
            <xsl:variable name="before"
                          select="normalize-space(substring-before(iana:range, 
                                  '-'))"/>
            <xsl:variable name="after"
                          select="normalize-space(substring-after(iana:range, 
                                  '-'))"/>
            <xsl:choose>
              <xsl:when test="$before and $after and
                              not(contains($before, ' ') or
                              contains($after, ' '))">
                <xsl:value-of select="$before"/>
                <xsl:text>, </xsl:text>
                <xsl:value-of select="$after"/>
              </xsl:when>
              <xsl:when test="starts-with($before, 'The valid range is')">
                <!-- Elements 412 and 413 contain bogus ranges.  Fix
                     them up here-->
                <xsl:value-of select="normalize-space(substring($before,
                                      19))"/>
                <xsl:text>, </xsl:text>
                <xsl:value-of
                    select="substring-before(concat(normalize-space(
                            translate($after, '.', ' ')), ' '), ' ')"/>
              </xsl:when>
              <xsl:otherwise>
                <!-- Ignore illegal ranges -->
                <!-- <xsl:text>&#10;#error Unknown range "</xsl:text> -->
                <!-- <xsl:value-of select="iana:range"/> -->
                <!-- <xsl:text>"&#10;</xsl:text> -->
                <xsl:text>0, 0</xsl:text>
              </xsl:otherwise>
            </xsl:choose>
          </xsl:otherwise>
        </xsl:choose>

        <!-- type -->
        <xsl:text>, </xsl:text>
        <xsl:choose>
          <xsl:when test="iana:dataType = 'octetArray'">
            <xsl:text>FB_OCTET_ARRAY</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned8'">
            <xsl:text>FB_UINT_8</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned16'">
            <xsl:text>FB_UINT_16</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned32'">
            <xsl:text>FB_UINT_32</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'unsigned64'">
            <xsl:text>FB_UINT_64</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'signed8'">
            <xsl:text>FB_INT_8</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'signed16'">
            <xsl:text>FB_INT_16</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'signed32'">
            <xsl:text>FB_INT_32</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'signed64'">
            <xsl:text>FB_INT_64</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'float32'">
            <xsl:text>FB_FLOAT_32</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'float64'">
            <xsl:text>FB_FLOAT_64</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'boolean'">
            <xsl:text>FB_BOOL</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'macAddress'">
            <xsl:text>FB_MAC_ADDR</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'string'">
            <xsl:text>FB_STRING</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'dateTimeSeconds'">
            <xsl:text>FB_DT_SEC</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'dateTimeMilliseconds'">
            <xsl:text>FB_DT_MILSEC</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'dateTimeMicroseconds'">
            <xsl:text>FB_DT_MICROSEC</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'dateTimeNanoseconds'">
            <xsl:text>FB_DT_NANOSEC</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'ipv4Address'">
            <xsl:text>FB_IP4_ADDR</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'ipv6Address'">
            <xsl:text>FB_IP6_ADDR</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'basicList'">
            <xsl:text>FB_BASIC_LIST</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'subTemplateList'">
            <xsl:text>FB_SUB_TMPL_LIST</xsl:text>
          </xsl:when>
          <xsl:when test="iana:dataType = 'subTemplateMultiList'">
            <xsl:text>FB_SUB_TMPL_MULTI_LIST</xsl:text>
          </xsl:when>
          <xsl:otherwise>
            <xsl:text>&#10;#error Unknown dataType "</xsl:text>
            <xsl:value-of select="iana:dataType"/>
            <xsl:text>"&#10;</xsl:text>
          </xsl:otherwise>
        </xsl:choose>

        <!-- description -->
        <xsl:text>, NULL),&#10;</xsl:text>
      </xsl:if>

    </xsl:for-each>
    <xsl:text>&#10;    FB_IE_NULL&#10;};&#10;</xsl:text>
  </xsl:template>
</xsl:stylesheet>
