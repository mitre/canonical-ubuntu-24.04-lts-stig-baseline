control 'SV-270747' do
  title 'Ubuntu 24.04 LTS handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system. 
 
This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.

'
  desc 'check', 'Note: If there is a documented and approved mission requirement for data-at-rest to not be encrypted, this requirement is not applicable. 
 
Verify Ubuntu 24.04 LTS prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.  

Determine the partition layout for the system with the following command: 
 
$ sudo fdisk -l 
(..) 
Disk /dev/vda: 15 GiB, 16106127360 bytes, 31457280 sectors 
Units: sectors of 1 * 512 = 512 bytes 
Sector size (logical/physical): 512 bytes / 512 bytes 
I/O size (minimum/optimal): 512 bytes / 512 bytes 
Disklabel type: gpt 
Disk identifier: 83298450-B4E3-4B19-A9E4-7DF147A5FEFB 
 
Device       Start      End  Sectors Size Type 
/dev/vda1     2048     4095     2048   1M BIOS boot 
/dev/vda2     4096  2101247  2097152   1G Linux filesystem 
/dev/vda3  2101248 31455231 29353984  14G Linux filesystem 
(...) 
 
Verify the system partitions are all encrypted with the following command: 
 
$ more /etc/crypttab
 
Every persistent disk partition present must have an entry in the file.  
 
If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding.'
  desc 'fix', 'To encrypt an entire partition, dedicate a partition for encryption in the partition layout. 
 
Note: Encrypting a partition in an already-installed system is more difficult because it will need to be resized and existing partitions changed.'
  impact 0.5
  tag check_id: 'C-74780r1066728_chk'
  tag severity: 'medium'
  tag gid: 'V-270747'
  tag rid: 'SV-270747r1066730_rule'
  tag stig_id: 'UBTU-24-600090'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-74681r1066729_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184', 'SRG-OS-000780-GPOS-00240']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476', 'CCI-004910']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)', 'SC-28 (3)']
end
