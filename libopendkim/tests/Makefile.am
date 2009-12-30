# $Id: Makefile.am,v 1.3 2009/12/22 00:12:55 cm-msk Exp $

AM_CFLAGS = $(COV_CFLAGS)
AM_LDFLAGS = $(COV_LDFLAGS)

if DEBUG
AM_CFLAGS += -g
endif

LDADD = ../libopendkim.la $(COV_LIBADD) $(LIBCRYPTO_LIBS)
AM_CPPFLAGS = -I..

PROF_SRCS = base64.c dkim-cache.c dkim-canon.c dkim-keys.c dkim-mailparse.c dkim-policy.c dkim-rep.c dkim-strl.c dkim-tables.c dkim-test.c dkim-ub.c dkim-util.c dkim.c util.c

check_PROGRAMS = t-setup t-test00 t-test01 t-test02 t-test03 t-test04 \
	t-test05 t-test06 t-test07 t-test08 t-test09 t-test10 t-test11 \
	t-test12 t-test13 t-test14 t-test15 t-test16 t-test17 t-test18 \
	t-test19 t-test20 t-test21 t-test22 t-test23 t-test24 t-test25 \
	t-test26 t-test27 t-test28 t-test29 t-test30 t-test31 t-test32 \
	t-test33 t-test34 t-test35 t-test36 t-test37 t-test38 t-test39 \
	t-test40 t-test41 t-test42 t-test43 t-test44 t-test45 t-test46 \
	t-test47 t-test48 t-test50 t-test51 t-test52 t-test53 \
	t-test54 t-test55 t-test56 t-test57 t-test58 t-test59 t-test60 \
	t-test61 t-test62 t-test63 t-test64 t-test65 t-test66 t-test67 \
	t-test68 t-test69 t-test70 t-test71 t-test72 t-test73 t-test74 \
	t-test75 t-test76 t-test77 t-test78 t-test79 t-test80 t-test81 \
	t-test82 t-test83 t-test84 t-test85 t-test86 t-test87 t-test88 \
	t-test89 t-test90 t-test91 t-test92 t-test93 t-test94 t-test95 \
	t-test96 t-test97 t-test98 t-test99 t-test100 t-test101 t-test102 \
	t-test103 t-test104 t-test105 t-test106 t-test107 t-test108 \
	t-test109 t-test110 t-test111 t-test112 t-test114 \
	t-test115 t-test116 t-test117 t-test119 t-test120 \
	t-test121 t-test122 t-test123 t-test124 t-test125 t-test126 \
	t-test127 t-test128 t-test129 t-test130 t-test131 \
	t-signperf t-verifyperf
if ALL_SYMBOLS
check_PROGRAMS += t-test49 t-test113 t-test118
endif
check_PROGRAMS += t-cleanup
TESTS = $(check_PROGRAMS)

t_setup_SOURCES = t-setup.c t-testdata.h
t_cleanup_SOURCES = t-cleanup.c t-testdata.h
t_signperf_SOURCES = t-signperf.c t-testdata.h
t_verifyperf_SOURCES = t-verifyperf.c t-testdata.h
t_test00_SOURCES = t-test00.c t-testdata.h
t_test01_SOURCES = t-test01.c t-testdata.h
t_test02_SOURCES = t-test02.c t-testdata.h
t_test03_SOURCES = t-test03.c t-testdata.h
t_test04_SOURCES = t-test04.c t-testdata.h
t_test05_SOURCES = t-test05.c t-testdata.h
t_test06_SOURCES = t-test06.c t-testdata.h
t_test07_SOURCES = t-test07.c t-testdata.h
t_test08_SOURCES = t-test08.c t-testdata.h
t_test09_SOURCES = t-test09.c t-testdata.h
t_test10_SOURCES = t-test10.c t-testdata.h
t_test11_SOURCES = t-test11.c t-testdata.h
t_test12_SOURCES = t-test12.c t-testdata.h
t_test13_SOURCES = t-test13.c t-testdata.h
t_test14_SOURCES = t-test14.c t-testdata.h
t_test15_SOURCES = t-test15.c t-testdata.h
t_test16_SOURCES = t-test16.c t-testdata.h
t_test17_SOURCES = t-test17.c t-testdata.h
t_test18_SOURCES = t-test18.c t-testdata.h
t_test19_SOURCES = t-test19.c t-testdata.h
t_test20_SOURCES = t-test20.c t-testdata.h
t_test21_SOURCES = t-test21.c t-testdata.h
t_test22_SOURCES = t-test22.c t-testdata.h
t_test23_SOURCES = t-test23.c t-testdata.h
t_test24_SOURCES = t-test24.c t-testdata.h
t_test25_SOURCES = t-test25.c t-testdata.h
t_test26_SOURCES = t-test26.c t-testdata.h
t_test27_SOURCES = t-test27.c t-testdata.h
t_test28_SOURCES = t-test28.c t-testdata.h
t_test29_SOURCES = t-test29.c t-testdata.h
t_test30_SOURCES = t-test30.c t-testdata.h
t_test31_SOURCES = t-test31.c t-testdata.h
t_test32_SOURCES = t-test32.c t-testdata.h
t_test33_SOURCES = t-test33.c t-testdata.h
t_test34_SOURCES = t-test34.c t-testdata.h
t_test35_SOURCES = t-test35.c t-testdata.h
t_test36_SOURCES = t-test36.c t-testdata.h
t_test37_SOURCES = t-test37.c t-testdata.h
t_test38_SOURCES = t-test38.c t-testdata.h
t_test39_SOURCES = t-test39.c t-testdata.h
t_test40_SOURCES = t-test40.c t-testdata.h
t_test41_SOURCES = t-test41.c t-testdata.h
t_test42_SOURCES = t-test42.c t-testdata.h
t_test43_SOURCES = t-test43.c t-testdata.h
t_test44_SOURCES = t-test44.c t-testdata.h
t_test45_SOURCES = t-test45.c t-testdata.h
t_test46_SOURCES = t-test46.c t-testdata.h
t_test47_SOURCES = t-test47.c t-testdata.h
t_test48_SOURCES = t-test48.c t-testdata.h
t_test49_SOURCES = t-test49.c t-testdata.h
t_test50_SOURCES = t-test50.c t-testdata.h
t_test51_SOURCES = t-test51.c t-testdata.h
t_test52_SOURCES = t-test52.c t-testdata.h
t_test53_SOURCES = t-test53.c t-testdata.h
t_test54_SOURCES = t-test54.c t-testdata.h
t_test55_SOURCES = t-test55.c t-testdata.h
t_test56_SOURCES = t-test56.c t-testdata.h
t_test57_SOURCES = t-test57.c t-testdata.h
t_test58_SOURCES = t-test58.c t-testdata.h
t_test59_SOURCES = t-test59.c t-testdata.h
t_test60_SOURCES = t-test60.c t-testdata.h
t_test61_SOURCES = t-test61.c t-testdata.h
t_test62_SOURCES = t-test62.c t-testdata.h
t_test63_SOURCES = t-test63.c t-testdata.h
t_test64_SOURCES = t-test64.c t-testdata.h
t_test65_SOURCES = t-test65.c t-testdata.h
t_test66_SOURCES = t-test66.c t-testdata.h
t_test67_SOURCES = t-test67.c t-testdata.h
t_test68_SOURCES = t-test68.c t-testdata.h
t_test69_SOURCES = t-test69.c t-testdata.h
t_test70_SOURCES = t-test70.c t-testdata.h
t_test71_SOURCES = t-test71.c t-testdata.h
t_test72_SOURCES = t-test72.c t-testdata.h
t_test73_SOURCES = t-test73.c t-testdata.h
t_test74_SOURCES = t-test74.c t-testdata.h
t_test75_SOURCES = t-test75.c t-testdata.h
t_test76_SOURCES = t-test76.c t-testdata.h
t_test77_SOURCES = t-test77.c t-testdata.h
t_test78_SOURCES = t-test78.c t-testdata.h
t_test79_SOURCES = t-test79.c t-testdata.h
t_test80_SOURCES = t-test80.c t-testdata.h
t_test81_SOURCES = t-test81.c t-testdata.h
t_test82_SOURCES = t-test82.c t-testdata.h
t_test83_SOURCES = t-test83.c t-testdata.h
t_test84_SOURCES = t-test84.c t-testdata.h
t_test85_SOURCES = t-test85.c t-testdata.h
t_test86_SOURCES = t-test86.c t-testdata.h
t_test87_SOURCES = t-test87.c t-testdata.h
t_test88_SOURCES = t-test88.c t-testdata.h
t_test89_SOURCES = t-test89.c t-testdata.h
t_test90_SOURCES = t-test90.c t-testdata.h
t_test91_SOURCES = t-test91.c t-testdata.h
t_test92_SOURCES = t-test92.c t-testdata.h
t_test93_SOURCES = t-test93.c t-testdata.h
t_test94_SOURCES = t-test94.c t-testdata.h
t_test95_SOURCES = t-test95.c t-testdata.h
t_test96_SOURCES = t-test96.c t-testdata.h
t_test97_SOURCES = t-test97.c t-testdata.h
t_test98_SOURCES = t-test98.c t-testdata.h
t_test99_SOURCES = t-test99.c t-testdata.h
t_test100_SOURCES = t-test100.c t-testdata.h
t_test101_SOURCES = t-test101.c t-testdata.h
t_test102_SOURCES = t-test102.c t-testdata.h
t_test103_SOURCES = t-test103.c t-testdata.h
t_test104_SOURCES = t-test104.c t-testdata.h
t_test105_SOURCES = t-test105.c t-testdata.h
t_test106_SOURCES = t-test106.c t-testdata.h
t_test107_SOURCES = t-test107.c t-testdata.h
t_test108_SOURCES = t-test108.c t-testdata.h
t_test109_SOURCES = t-test109.c t-testdata.h
t_test110_SOURCES = t-test110.c t-testdata.h
t_test111_SOURCES = t-test111.c t-testdata.h
t_test112_SOURCES = t-test112.c t-testdata.h
if ALL_SYMBOLS
t_test113_SOURCES = t-test113.c t-testdata.h
endif
t_test114_SOURCES = t-test114.c t-testdata.h
t_test115_SOURCES = t-test115.c t-testdata.h
t_test116_SOURCES = t-test116.c t-testdata.h
t_test117_SOURCES = t-test117.c t-testdata.h
if ALL_SYMBOLS
t_test118_SOURCES = t-test118.c t-testdata.h
endif
t_test119_SOURCES = t-test119.c t-testdata.h
t_test120_SOURCES = t-test120.c t-testdata.h
t_test121_SOURCES = t-test121.c t-testdata.h
t_test122_SOURCES = t-test122.c t-testdata.h
t_test123_SOURCES = t-test123.c t-testdata.h
t_test124_SOURCES = t-test124.c t-testdata.h
t_test125_SOURCES = t-test125.c t-testdata.h
t_test126_SOURCES = t-test126.c t-testdata.h
t_test127_SOURCES = t-test127.c t-testdata.h
t_test128_SOURCES = t-test128.c t-testdata.h
t_test129_SOURCES = t-test129.c t-testdata.h
t_test130_SOURCES = t-test130.c t-testdata.h
t_test131_SOURCES = t-test131.c t-testdata.h

MOSTLYCLEANFILES=

if GCOV_ONLY
MOSTLYCLEANFILES+=*.gcov *.gcno *.gcda *.bb *.bbg *.da .gcov-files
TESTS_ENVIRONMENT=./gcov-helper.sh

.gcov-files: check-TESTS
	for i in $(PROF_SRCS); do \
		x=`echo $$i | sed 's/\..*//g'`; \
		if test -f ../libopendkim_la-$$x.gcno -a \
		        -f ../libopendkim_la-$$x.gcda; then \
			mv ../libopendkim_la-$$x.gcno ../$$x.gcno; \
			mv ../libopendkim_la-$$x.gcda ../$$x.gcda; \
			gcov -o .. $$i; \
		fi; \
		if test -f ../libopendkim_la-$$x.bb -a \
		        -f ../libopendkim_la-$$x.bbg -a \
		        -f ../libopendkim_la-$$x.da; then \
			mv ../libopendkim_la-$$x.bb ../$$x.bb; \
			mv ../libopendkim_la-$$x.bbg ../$$x.bbg; \
			mv ../libopendkim_la-$$x.da ../$$x.da; \
			gcov -o .. $$i; \
		fi; \
	done
	touch $@

check-local: .gcov-files
endif

if LCOV
dist_doc_DATA=lcov
MAINTAINERCLEANFILES=description.txt description.html
MOSTLYCLEANFILES+=*.info .prepare-lcov .info-files *.gcno *.gcda

.info-files: check-TESTS 
	for i in $(PROF_SRCS); do \
		x=`echo $$i | sed 's/\..*//g'`; \
		if test -f ../libopendkim_la-$$x.gcno -a \
		        -f ../libopendkim_la-$$x.gcda; then \
			mv ../libopendkim_la-$$x.gcno ../$$x.gcno; \
			mv ../libopendkim_la-$$x.gcda ../$$x.gcda; \
		fi; \
		lcov --capture --directory .. --output-file $$x.info \
			--test-name $$x -q; \
	done
	touch .info-files

check-local: .info-files description.html
	genhtml --output-directory lcov *.info --show-details --highlight \
		--frames --legend  --title @PACKAGE@ \
		--description-file description.html

description.txt:
	for i in $(PROF_SRCS); do \
		fgrep '***' ../$$i | \
			sed -e 's/^t-\([a-z0-9]*\)\.c:[^*]*\*\*\*\(.*\)\\n.*/\1\n\t\2\n/g' >> $@; \
	done
 
description.html: description.txt
	gendesc --output $@ $?

maintainer-clean-local:
	-rm -rf lcov/[^C]*

.PHONY: maintainer-clean-local check-local
endif

if GPROF
MOSTLYCLEANFILES+=*.prof gmon.out *.gmon

check-local: check-TESTS
	for i in $(check_PROGRAMS); do \
		./$$i; \
		gprof $$i > $$i.prof; \
	done
endif