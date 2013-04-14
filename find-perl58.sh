#!/bin/sh
# Alas, perl 5.8 doesn't install a perl5.8 the way 5.6 installed perl5.6

need_minor=8
oIFS="$IFS"
IFS=:
set $PATH
IFS="$oIFS"

p58=''
for d ; do
	for n in perl5 perl ; do
		if [ -x "$d/$n" ]; then
			try="$d/$n"
			min=`"$try" -le 'print $]' | cut -d . -f 2 | cut -c 1-3`
			min=`echo "$min" | sed 's/^00*//'`
			expr $min \>= $need_minor >/dev/null 2>&1
			if [ $? -eq 0 ]; then
				p58="$try"
				break 2
			fi
		fi
	done
done

if [ ".$p58" != "." ]; then
	echo "$p58"
	exit 0
fi
echo >&2 "$0: Failed to find a Perl >= 5.8 interpreter"
exit 1
