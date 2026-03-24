control 'SV-278917' do
  title 'Ubuntu 24.04 LTS must be a vendor-supported release.'
  desc 'An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

The support status of the OS depends on its subscription status.

End Of Life dates for Ubuntu 24.04 releases are as follows:
Standard Support: April 2029
Extended Security Maintenance (ESM): April 2036

ESM is available via an Ubuntu Pro subscription.'
  desc 'check', 'Verify the version of Ubuntu 24.04 LTS is vendor supported with the following command:

$ grep DISTRIB_DESCRIPTION /etc/lsb-release
DISTRIB_DESCRIPTION="Ubuntu 24.04.3 LTS"

Check the subscription status of the system with the following command:
$ pro status

If the installed version of Ubuntu 24.04 LTS is not supported, this is a finding.'
  desc 'fix', 'Upgrade to a supported version of Ubuntu 24.04 LTS.'
  impact 0.7
  tag check_id: 'C-83451r1155233_chk'
  tag severity: 'high'
  tag gid: 'V-278917'
  tag rid: 'SV-278917r1155246_rule'
  tag stig_id: 'UBTU-24-700400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-83356r1134999_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  lsb = parse_config_file('/etc/lsb-release')

  describe 'Ubuntu release description' do
    subject { lsb['DISTRIB_DESCRIPTION'] || '' }
    it { should match(/Ubuntu\s+24\.04(?:\.\d+)?\s+LTS/i) }
  end

  # Lifecycle windows derived from STIG narrative
  standard_support_eol = Time.new(2029, 4, 30, 23, 59, 59, '+00:00')
  esm_support_eol = Time.new(2036, 4, 30, 23, 59, 59, '+00:00')
  now = Time.now.utc

  if now <= standard_support_eol
    # Within standard support window; vendor support available without subscription
    describe 'Vendor support status within standard support window' do
      subject { now <= standard_support_eol }
      it { should be true }
    end
  elsif now <= esm_support_eol
    # Within ESM window; verify Ubuntu Pro subscription status
    pro_status = command('pro status')

    if pro_status.exit_status != 0 || pro_status.stdout.strip.empty?
      describe 'Ubuntu Pro tooling unavailable' do
        skip 'Ubuntu Pro tooling not available; manual verification of ESM subscription status is required.'
      end
    else
      describe.one do
        describe 'Ubuntu Pro attached' do
          subject { pro_status.stdout }
          it { should match(/attached/i) }
          it { should_not match(/not\s+attached/i) }
        end

        describe 'ESM services enabled' do
          subject { pro_status.stdout }
          it { should match(/(?mi)\besm-(apps|infra)\b.*\benabled\b/) }
        end
      end
    end
  else
    # Beyond ESM end-of-life; release is no longer vendor supported
    describe 'Ubuntu 24.04 LTS ESM end-of-life status' do
      it 'is within vendor support lifecycle' do
        expect(now <= esm_support_eol).to be true, "Vendor support for Ubuntu 24.04 LTS ended on #{esm_support_eol.utc.strftime('%Y-%m-%d')}; current date: #{now.utc.strftime('%Y-%m-%d')}"
      end
    end
  end
end
