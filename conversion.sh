# Unzip hitlist.fsdb.bz2 -> hitlist.fsdb (requires bzip2 to be installed)
#sudo bzip2 -d internet_address_verfploeter_hitlist_it102w-20230125.fsdb.bz2

# Convert hitlist.fsdb (ip address byte format) to hitlist.txt (only storing the most responsive host for each prefix (i.e. the first listed address for each prefix))
#awk '{ split($2, targets, ","); if (targets[1] != "-") { printf "%d.%d.%d.%s\n", strtonum("0x" substr($1, 1, 2)), strtonum("0x" substr($1, 3, 2)), strtonum("0x" substr($1, 5, 2)), (targets[1] != "-" ? strtonum("0x" targets[1]) : "0"); } else { printf "%d.%d.%d.%d\n", strtonum("0x" substr($1, 1, 2)), strtonum("0x" substr($1, 3, 2)), strtonum("0x" substr($1, 5, 2)), 0; } }' internet_address_verfploeter_hitlist_it102w-20230125.fsdb > output_file.txt
