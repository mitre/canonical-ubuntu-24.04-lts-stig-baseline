control 'SV-270699' do
  title 'Ubuntu 24.04 LTS library files must be group-owned by root or a system account.'
  desc 'If Ubuntu 24.04 LTS were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" are group owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec stat -c "%n %G" {} +

If any output is returned, this is a finding.)
  desc 'fix', %q(Configure the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" to be group owned by root with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec chown :root {} +)
  impact 0.5
  tag check_id: 'C-74732r1101752_chk'
  tag severity: 'medium'
  tag gid: 'V-270699'
  tag rid: 'SV-270699r1107310_rule'
  tag stig_id: 'UBTU-24-300009'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-74633r1107309_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_files = command("find #{input('system_libraries').join(' ')} -type f -name '*.so*' ! -group root -exec stat -c '%n %G' {} +").stdout.split("\n")

  describe 'System libraries' do
    it 'should be group-owned by root' do
      expect(failing_files).to be_empty, "Files not group-owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
