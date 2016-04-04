MAINTAINER = "Bo Bayles <bbayles+netsa@gmail.com>"
VERSION = 20160403
PROC_ARC ?= amd64
TARGET_ROOT = $(shell pwd)/packaging/root
YAF_PREFIX = ${TARGET_ROOT}/opt/yaf
SILK_PREFIX = ${TARGET_ROOT}/opt/silk
LIBFIXBUF_PREFIX = ${TARGET_ROOT}/opt/libfixbuf
OUTPUT_DIR = $(shell pwd)/packaging/output

libfixbuf:
	mkdir -p ${LIBFIXBUF_PREFIX}
	(cd libfixbuf-src; \
		autoreconf -if; \
		./configure --prefix="${LIBFIXBUF_PREFIX}")
	make -C libfixbuf-src
	make -C libfixbuf-src install

yaf:
	mkdir -p ${YAF_PREFIX}
	(cd yaf-src; \
		autoreconf -if; \
		PKG_CONFIG_PATH="${LIBFIXBUF_PREFIX}/lib/pkgconfig" ./configure \
			--prefix="${YAF_PREFIX}")
	make -C yaf-src
	make -C yaf-src install

silk:
	mkdir -p ${SILK_PREFIX}
	(cd silk-src; \
		autoreconf -if; \
		./configure \
			--with-libfixbuf="${LIBFIXBUF_PREFIX}/lib/pkgconfig" \
			--enable-ipv6 \
			--prefix="${SILK_PREFIX}")
	make -C silk-src
	make -C silk-src install

deb:
	fpm \
		-s dir \
		-t deb \
		-n netsa-pkg \
		-v ${VERSION} \
		-p packaging/output/netsa-pkg.deb \
		-a ${PROC_ARC} \
		--maintainer ${MAINTAINER} \
		--category admin \
		--force \
		--deb-compression bzip2 \
		--description "YAF and SiLK from CERT NetSA Security Suite" \
		--license "GPL version 2, LGPL version 2.1" \
		--depends libglib2.0-0 \
		--depends liblzo2-2 \
		--depends libltdl7 \
		--depends libpcap0.8 \
		--depends zlib1g \
		--after-install packaging/scripts/postinst.sh \
		--after-remove packaging/scripts/postrm.sh \
		--deb-no-default-config-files \
		packaging/root/=/

rpm:
	fpm \
		-s dir \
		-t rpm \
		-n netsa-pkg \
		-v ${VERSION} \
		-p packaging/output/netsa-pkg.rpm \
		-a ${PROC_ARC} \
		--maintainer ${MAINTAINER} \
		--category admin \
		--force \
		--rpm-compression bzip2 \
		--description "YAF and SiLK from CERT NetSA Security Suite" \
		--license "GPL version 2, LGPL version 2.1" \
		--depends glib2 \
		--depends libpcap \
		--depends libtool-ltdl \
		--depends lzo \
		--depends zlib \
		--after-install packaging/scripts/postinst.sh \
		--after-remove packaging/scripts/postrm.sh \
		packaging/root/=/

build_deb: libfixbuf yaf silk deb

build_rpm: libfixbuf yaf silk rpm

build_ubuntu:
	$(eval IMAGE_ID = $(shell docker build --force-rm -q -f "packaging/scripts/buildimage_ubuntu-12.04/Dockerfile" .))
	docker run -v "${OUTPUT_DIR}:/netsa-pkg/packaging/output" $(IMAGE_ID) /usr/bin/make build_deb
	chmod -R 776 ${OUTPUT_DIR}/*

build_centos:
	$(eval IMAGE_ID = $(shell docker build --force-rm -q -f "packaging/scripts/buildimage_centos-6/Dockerfile" .))
	docker run -v "${OUTPUT_DIR}:/netsa-pkg/packaging/output" $(IMAGE_ID) /usr/bin/make build_rpm
	chmod -R 776 ${OUTPUT_DIR}/*

clean:
	git clean -dxf
