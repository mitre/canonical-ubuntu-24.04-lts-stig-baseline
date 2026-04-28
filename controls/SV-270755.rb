control 'SV-270755' do
  title 'Ubuntu 24.04 LTS must disable all wireless network adapters.'
  desc 'Without protection of communications with wireless peripherals, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read, altered, or used to compromise Ubuntu 24.04 LTS.

This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with an operating system. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR Keyboards, Mice, and Pointing Devices and Near Field Communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the approving authority (AO). Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that need to be protected, modification of communications with these wireless peripherals may be used to compromise Ubuntu 24.04 LTS. Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of communications with wireless peripherals can be accomplished by physical means (e.g., employing physical barriers to wireless radio frequencies) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa. If the wireless peripheral is only passing telemetry data, encryption of the data may not be required.'
  desc 'check', 'Note: This requirement is not applicable for systems that do not have physical wireless network radios.

Verify there are no wireless interfaces configured on the system with the following command:

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename

If a wireless interface is configured and has not been documented and approved by the information system security officer (ISSO), this is a finding.'
  desc 'fix', 'List all the wireless interfaces with the following command:

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename

For each interface, configure the system to disable wireless network interfaces with the following command:

$ sudo ifdown <interface name>

For each interface listed, find their respective module with the following command:

$ basename $(readlink -f /sys/class/net/<interface name>/device/driver)

where <interface name> must be substituted by the actual interface name.

Create a file in the "/etc/modprobe.d" directory and for each module, add the following line:

install <module name> /bin/true

For each module from the system, execute the following command to remove it:

$ sudo modprobe -r <module name>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000481-GPOS-00481'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000481-GPOS-000481', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000481-GPOS-00481']
  tag gid: 'V-270755'
  tag rid: 'SV-270755r1066754_rule'
  tag stig_id: 'UBTU-24-600230'
  tag fix_id: 'F-74689r1066753_fix'
  tag cci: ['CCI-001444', 'CCI-001443', 'CCI-002418', 'CCI-002421']
  tag nist: ['AC-18 (1)', 'SC-8', 'SC-8 (1)']
  tag 'host'
  tag 'container'

  if input('wifi_hardware')
    describe command('nmcli device') do
      its('stdout.strip') { should_not match(/wifi\s*connected/) }
    end
  else
    impact 0.0
    describe 'Skip' do
      skip 'The system does not have a wireless network adapter, this control is Not Applicable.'
    end
  end
end
