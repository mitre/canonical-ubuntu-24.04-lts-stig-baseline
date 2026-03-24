control 'SV-270757' do
  title 'Ubuntu 24.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.'
  desc 'Any operating system providing too much information in error messages risks compromising the data and security of the structure, and content of error messages must be carefully considered by the organization.

Organizations carefully consider the structure/content of error messages. The extent to which information systems are able to identify and handle error conditions is guided by organizational policy and operational requirements. Information that could be exploited by adversaries includes, for example, erroneous logon attempts with passwords entered by mistake as the username, mission/business information that can be derived from (if not stated explicitly by) information recorded, and personal information, such as account numbers, social security numbers, and credit card numbers.'
  desc 'check', 'Verify the /run/log/journal and /var/log/journal directories have permissions set to "2640" or less permissive with the following command:

$ sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %a" {} \\;
/run/log/journal 2640
/var/log/journal 2640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e 2640

If any output returned has a permission set greater than 2640, this is a finding.

Verify all files in the /run/log/journal and /var/log/journal directories have permissions set to "640" or less permissive with the following command:

$ sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \\;
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system.journal 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000@0005f97cd4a8c9b5a.journal~ 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cd2a1e0a7-d58b848af46813a4.journal~ 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/system@0005f97cb900e501-55ea053b7f75ae1c.journal~ 640
/var/log/journal/d5745ad455d34fb8b6f78be37c1fcd3e/user-1000.journal 640

If any output returned has a permission set greater than "640", this is a finding.'
  desc 'fix', 'Configure the system to set the appropriate permissions to the files and directories used by the systemd journal:

$ sudo nano /usr/lib/tmpfiles.d/systemd.conf

Edit the following lines of the configuration file:

z /run/log/journal 2640 root systemd-journal - -
Z /run/log/journal/%m ~2640 root systemd-journal - -
z /var/log/journal 2640 root systemd-journal - -
z /var/log/journal/%m 2640 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -

Note: The system must be restarted for these settings to take effect.'
  impact 0.5
  tag check_id: 'C-74790r1066758_chk'
  tag severity: 'medium'
  tag gid: 'V-270757'
  tag rid: 'SV-270757r1066760_rule'
  tag stig_id: 'UBTU-24-700020'
  tag gtitle: 'SRG-OS-000205-GPOS-00083'
  tag fix_id: 'F-74691r1066759_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
  tag 'host'
  tag 'container'

  expected_modes = input('expected_modes')

  journal_dirs = command('find /run/log/journal /var/log/journal  -type d -exec stat -c "%n" {} \;').stdout.split("\n")
  dir_mode = expected_modes['journal_dir']
  non_compliant_journal_dirs = journal_dirs.select { |dir| file(dir).more_permissive_than?(dir_mode) }

  describe 'All journal directories' do
    it "have a mode of '#{dir_mode}' or less permissive" do
      expect(non_compliant_journal_dirs).to be_empty, "Failing directories:\n\t- #{non_compliant_journal_dirs.join("\n\t- ")}"
    end
  end

  journal_files = command('sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n" {} \;').stdout.split("\n")
  file_mode = expected_modes['journal_file']
  non_compliant_journal_files = journal_files.select { |f| file(f).more_permissive_than?(file_mode) }

  describe 'Journal files' do
    it "have a mode of '#{file_mode}' or less permissive" do
      expect(non_compliant_journal_files).to be_empty, "Failing files:\n\t- #{non_compliant_journal_files.join("\n\t- ")}"
    end
  end
end
