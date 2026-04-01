control 'SV-270682' do
  title 'Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours.'
  desc 'Temporary accounts are privileged or nonprivileged accounts established during pressing circumstances, such as new software or hardware configuration or an incident response, where the need for prompt account activation requires bypassing normal account authorization procedures. If any inactive temporary accounts are left enabled on the system and are not either manually removed or automatically expired within 72 hours, the security posture of the system will be degraded and exposed to exploitation by unauthorized users or insider threat actors.

Temporary accounts are different from emergency accounts. Emergency accounts, also known as "last resort" or "break glass" accounts, are local logon accounts enabled on the system for emergency use by authorized system administrators to manage a system when standard logon methods are failing or not available. Emergency accounts are not subject to manual removal or scheduled expiration requirements.

The automatic expiration of temporary accounts may be extended as needed by the circumstances but it must not be extended indefinitely. A documented permanent account must be established for privileged users who need long-term maintenance accounts.

'
  desc 'check', 'Verify temporary accounts have been provisioned with an expiration date of 72 hours with the following command:

$ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to expire temporary accounts after 72 hours with the following command:

$ sudo chage -E $(date -d +3days +%Y-%m-%d) <temporary_account_name>'
  impact 0.5
  tag check_id: 'C-74715r1066533_chk'
  tag severity: 'medium'
  tag gid: 'V-270682'
  tag rid: 'SV-270682r1066535_rule'
  tag stig_id: 'UBTU-24-200250'
  tag gtitle: 'SRG-OS-000002-GPOS-00002'
  tag fix_id: 'F-74616r1066534_fix'
  tag satisfies: ['SRG-OS-000002-GPOS-00002', 'SRG-OS-000123-GPOS-00064']
  tag 'documentable'
  tag cci: ['CCI-000016', 'CCI-001682']
  tag nist: ['AC-2 (2)', 'AC-2 (2)']
  tag 'host'
  tag 'container'

  tmp_users = input('temporary_accounts')

  tmp_max_days = input('temporary_account_max_days')

  if tmp_users.empty?
    describe 'Temporary accounts' do
      subject { tmp_users }
      it { should be_empty }
    end
  else
    tmp_users_existing = tmp_users.select { |u| user(u).exists? }
    failing_users = tmp_users_existing.select { |u| user(u).maxdays > tmp_max_days }
    missing_users = tmp_users - tmp_users_existing

    describe 'Temporary accounts' do
      if tmp_users_existing.any?
        it "should have expiration times less than or equal to '#{tmp_max_days}' days" do
          expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
        end
      end
      if missing_users.any?
        it "(input users: '#{missing_users.join("', '")}') were not found on this system" do
          expect(missing_users).not_to be_empty
        end
      end
    end
  end
end
