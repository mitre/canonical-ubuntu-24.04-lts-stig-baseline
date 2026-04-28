control 'SV-270720' do
  title 'Ubuntu 24.04 LTS must uniquely identify interactive users.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', %q(Verify Ubuntu 24.04 LTS contains no duplicate User IDs (UIDs) for interactive users with the following command:

$ awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced and the accounts listed are interactive user accounts, this is a finding.)
  desc 'fix', 'Edit the file "/etc/passwd" and provide each interactive user account that has a duplicate UID with a unique UID.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062', 'SRG-OS-000042-GPOS-00020']
  tag gid: 'V-270720'
  tag rid: 'SV-270720r1066649_rule'
  tag stig_id: 'UBTU-24-400000'
  tag fix_id: 'F-74654r1066648_fix'
  tag cci: ['CCI-000764', 'CCI-000135', 'CCI-000804']
  tag nist: ['IA-2', 'AU-3 (1)', 'IA-8']
  tag 'host'
  tag 'container'

  user_count = passwd.where { uid.to_i >= 1000 }.entries.length

  describe "Count of interactive unique user IDs should match interactive user count (#{user_count}): UID count" do
    subject { passwd.where { uid.to_i >= 1000 }.uids.uniq.length }
    it { should eq user_count }
  end
end
