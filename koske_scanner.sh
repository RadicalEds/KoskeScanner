#!/bin/bash
#####################################
VERSION="0.1"
NAME="Koske Scanner"
AUTHOR="RadicalEd"
DESCRIPTION="Scan Known Filetypes For Data Thats Been Appended To Them."
LICENSE="Whatever"
PROGRAM=$0
BANNERCOLOR="cyan"
HIGHLIGHT="red"
#####################################

# Inspired By Koske Miner AI Generated Malware

# https://www.bleepingcomputer.com/news/security/new-koske-linux-malware-hides-in-cute-panda-images/

# Upon Inspection of Panda Images, Malware is Appended to the End of File
# This Script Searches For The End Of File Marker and Determines if it really is the End.

#####################################
# Printing Functions

c () { # Set/Clear Colors
	case "${1}" in
		(black)	  tput setaf 0;;
		(red)		tput setaf 1;;
		(green)	  tput setaf 2;;
		(yellow)	 tput setaf 3;;
		(blue)	   tput setaf 4;;
		(magenta)	tput setaf 5;;
		(cyan)	   tput setaf 6;;
		(white)	  tput setaf 7;;
		(bg_black)   tput setab 0;;
		(bg_red)	 tput setab 1;;
		(bg_green)   tput setab 2;;
		(bg_yellow)  tput setab 3;;
		(bg_blue)	tput setab 4;;
		(bg_magenta) tput setab 5;;
		(bg_cyan)	tput setab 6;;
		(bg_white)   tput setab 7;;
		(n)		  tput sgr0;;
		(none)	   tput sgr0;;
		(clear)	  tput sgr0;;
	esac
}

banner () {
cat << 'EOF' >&2 | sed -e "s/@/$(c magenta)@$(c n)/g"
8  dP            8             .d88b.                                  
8wdP  .d8b. d88b 8.dP .d88b    YPwww. .d8b .d88 8d8b. 8d8b. .d88b 8d8b 
88Yb  8' .8 `Yb. 88b  8.dP'        d8 8    8  8 8P Y8 8P Y8 8.dP' 8P   
8  Yb `Y8P' Y88P 8 Yb `Y88P    `Y88P' `Y8P `Y88 8   8 8   8 `Y88P 8    
EOF
}


usage () {
c "$BANNERCOLOR"
banner
c n

cat << EOF >&2

$(c $HIGHLIGHT)$NAME$(c n) v$VERSION - Written By $(c $HIGHLIGHT)$AUTHOR$(c n)

$(echo -n "	$DESCRIPTION" | fmt -w $(tput cols))

$(c $HIGHLIGHT)USAGE$(c n): $PROGRAM [-h] [-f] [-l list] [files/directories...]

	-h      : show usage
	-f      : scan faster by keeping null bytes (creates false positives)
	-l list : read from a list of files and directories to scan
	-2      : detect whether the trailer has been specified atleast twice

EOF
}

error () {
	code="$1";shift
	case "$code" in
		(1) usage;;
	esac
	echo "Error $code: $*" >&2
	exit "$code"
}

hr () { # Horizontal Rule
	character="${1:--}"
	printf -v _hr "%*s" $(tput cols) && echo "${_hr// /$character}";
}

say () {
	echo -e "$*" >&2
}

statusline () {
	echo -e -n "\r$*" >&2
}

clearline () {
	printf "%*s" $(tput cols);
	echo -e -n "\r"
}

# End of Printing Functions
#####################################
# Arguments

while getopts "hfl:" o;do
	case "${o}" in
		(h) usage && exit;;
		(f) FAST=true;;
		(l) LIST="$(OPTARG)";;
		(2) DOUBLE_TRAILER=true;;
		(*) echo "Try Using $PROGRAM -h for Help And Information" >&2 && exit 1;;
	esac
done

shift $((OPTIND-1))

# End of Arguments
#####################################
# Functions

print_bytes () { # Output Known Header/Trailer Bytes
	options=( jpg_header jpg_footer png_header png_footer )
 
	case "$1" in
		${options[0]}) # jpg_header
			bytes="\xFF\xD8"
			;;
		${options[1]}) # jpg_footer
			bytes="\xFF\xD9"
			;;
		${options[2]}) # png_header
			bytes="\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
			;;
		${options[3]}) # png_footer
			bytes="\x49\x45\x4E\x44\xAE\x42\x60\x82"
			;;
		*)
			echo "Available Options: ${options[*]}"
			exit 1
			;;
	esac
	echo -ne "${bytes}"
}

tailWithoutNulls () { #length #file
	# Reads the last 100 bytes, removes nullbytes, and returns the last x bytes of that chunk
	chunksize=100; length="${1}"; file="${2}";
	bytes="$(tail -c "${chunksize}" "${file}" | tr -d '\0' | tail -c ${length})";
	echo -n "${bytes}"
}

test_endbytes () { #input_bytes #filename
	input_bytes="${1}"; file="${2}";
	length="$(echo -n "$input_bytes"|wc -c)"
	if [ "$FAST" ];then
		# look for exact bytes
		out_bytes="$(tail -c "$length" "$file")"
	else
		# remove null bytes first
		out_bytes="$(tailWithoutNulls "$length" "$file")"
	fi
	[ "$out_bytes" == "$input_bytes" ] && return 0 || return 1
}

scan_target () {
	target="$1"
	find "$target" -type f -iregex '.*.jpg\|.*.jpeg\|.*.png' | while read file;do
		case "${file/*./}" in
			(png)  trailer="$(print_bytes png_footer)";;
			(jpg)  trailer="$(print_bytes jpg_footer)";;
			(jpeg) trailer="$(print_bytes jpg_footer)";;
		esac
		statusline "Scanning: $(basename "$file")"
		test_endbytes "${trailer}" "${file}" || {
			clearline
			echo "${file}"
		}
	done
}

# End of Functions
#####################################
# Execution

[ ! "$LIST" ] && [ ! "$1" ] && error 2 "We Need A File Or Directory To Scan"

c "$BANNERCOLOR"
banner
c none

hr

say "Scanning Targets..."

if [ "$LIST" ];then
	cat "$LIST" | while read target;do
		scan_target "$target"
	done
fi

while [ ! -z "$1" ]; do
    target="$1"; shift;
	scan_target "$target"
done

clearline
say "Finished Scanning All Targets"

# End of Execution
#####################################
