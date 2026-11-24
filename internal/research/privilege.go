package research

import "sort"

type Technique struct { ID,Platform,Fact,Name,Remediation string;Priority int }
type PrivilegeCandidate struct { Technique Technique;Status,Reason string }

// Facts are supplied configuration assertions. Matching a rule identifies a
// review candidate; it neither inspects an OS nor asserts successful escalation.
func Techniques()[]Technique{
	linux:=[][3]string{
		{"sudo.nopasswd_all","Unrestricted passwordless sudo","Restrict sudo commands and require appropriate authentication."},
		{"sudo.setenv","sudo environment preservation","Remove unnecessary SETENV privileges."},
		{"sudo.binary_writable","Writable sudo command","Remove write permission on privileged executables."},
		{"sudo.preload_preserved","Loader variables preserved by sudo","Remove loader variables from privileged environments."},
		{"files.suid_shell","Setuid shell executable","Remove unnecessary setuid bits."},
		{"files.suid_interpreter","Setuid scripting interpreter","Remove interpreter setuid permissions."},
		{"capability.setuid","CAP_SETUID on executable","Remove unnecessary executable capabilities."},
		{"capability.dac_read_search","Read-bypass capability","Restrict CAP_DAC_READ_SEARCH."},
		{"capability.sys_admin","Broad administrative capability","Remove CAP_SYS_ADMIN where not required."},
		{"cron.root_writable","Writable privileged cron entry","Restrict cron configuration ownership."},
		{"cron.path_writable","Writable cron search path","Use absolute executable paths in scheduled jobs."},
		{"service.unit_writable","Writable privileged unit file","Restrict unit file and override permissions."},
		{"service.binary_writable","Writable privileged service binary","Restrict service executable permissions."},
		{"path.root_writable","Writable privileged PATH directory","Remove writable directories from privileged PATH."},
		{"docker.socket_writable","Container daemon socket access","Restrict daemon socket access."},
		{"docker.group_member","Container administration group membership","Treat container administration as privileged access."},
		{"lxd.group_member","LXD administration membership","Restrict LXD administration membership."},
		{"nfs.no_root_squash","NFS root identity preserved","Enable root squashing for untrusted clients."},
		{"credentials.shadow_readable","Password hash file readable","Restrict credential file permissions."},
		{"credentials.private_key_readable","Private key readable","Restrict key access and rotate exposed keys."},
		{"container.privileged","Privileged container","Remove unnecessary privileged container mode."},
		{"container.host_mount_rw","Writable host filesystem mount","Use minimal read-only host mounts."},
		{"kernel.unpatched","Unpatched kernel asserted","Validate vendor advisories and install supported updates."},
		{"polkit.unpatched","Unpatched polkit asserted","Validate affected package versions and apply vendor updates."},
		{"ptrace.permissive","Permissive process tracing policy","Restrict tracing of sensitive processes."},
		{"dbus.policy_broad","Broad privileged D-Bus policy","Review D-Bus service authorization policy."},
	}
	windows:=[][3]string{
		{"service.unquoted_path","Unquoted service executable path","Quote service paths and restrict parent directory writes."},
		{"service.binary_writable","Writable service executable","Restrict service binary ACLs."},
		{"service.config_modifiable","Modifiable privileged service configuration","Restrict service configuration rights."},
		{"task.action_writable","Writable scheduled task action","Restrict scheduled task executable ACLs."},
		{"task.highest_untrusted","Untrusted task runs at highest privileges","Limit privileged scheduled task identities."},
		{"token.impersonate","Impersonation privilege asserted","Restrict unnecessary impersonation privileges."},
		{"token.assign_primary","Primary token assignment privilege","Restrict token assignment privileges."},
		{"token.backup","Backup privilege asserted","Restrict backup operator privileges."},
		{"token.restore","Restore privilege asserted","Restrict restore privileges."},
		{"token.debug","Debug privilege asserted","Restrict debugging of privileged processes."},
		{"token.load_driver","Driver loading privilege","Restrict driver installation and enforce signing."},
		{"token.take_ownership","Take-ownership privilege","Review ownership-change permissions."},
		{"uac.policy_weak","Weak UAC policy asserted","Review UAC policy against the deployment baseline."},
		{"msi.always_elevated","AlwaysInstallElevated enabled","Disable elevated installation for untrusted packages."},
		{"registry.autorun_writable","Writable privileged autorun entry","Restrict autorun registry ACLs."},
		{"dll.search_path_writable","Writable DLL search directory","Harden DLL search paths and directory ACLs."},
		{"dll.missing_dependency","Missing privileged DLL dependency","Use trusted absolute library paths."},
		{"credentials.lsass_unprotected","Credential process protection absent","Enable appropriate credential protections."},
		{"credentials.sam_readable","SAM data readable","Restrict registry and backup credential data access."},
		{"credentials.unattend_secret","Unattended deployment secret present","Remove deployment secrets and rotate exposed credentials."},
		{"credentials.gpp_cached","Cached policy credential asserted","Remove cached policy credentials and rotate passwords."},
		{"startup.folder_writable","Writable privileged startup folder","Restrict startup folder ACLs."},
		{"group.local_admin","Local administrator membership","Review least-privilege group membership."},
		{"kernel.unpatched","Unpatched Windows kernel asserted","Validate vendor advisories and patch level."},
		{"driver.vulnerable_loaded","Vulnerable driver asserted","Verify driver advisories and block affected drivers."},
		{"com.registration_writable","Writable elevated COM registration","Restrict COM registration ACLs."},
	}
	var rules []Technique
	for _,group:=range []struct{name string;rows [][3]string}{{"linux",linux},{"windows",windows}}{for _,row:=range group.rows{rules=append(rules,Technique{ID:group.name+"."+row[0],Platform:group.name,Fact:group.name+"."+row[0],Name:row[1],Remediation:row[2],Priority:3})}}
	return rules
}

func RankPrivileges(facts map[string]bool)[]PrivilegeCandidate{
	var result []PrivilegeCandidate
	for _,rule:=range Techniques(){if facts[rule.Fact]{priority:=rule.Priority;if rule.Fact=="linux.sudo.nopasswd_all"||rule.Fact=="windows.msi.always_elevated"||rule.Fact=="linux.docker.socket_writable"{priority=5};rule.Priority=priority;result=append(result,PrivilegeCandidate{Technique:rule,Status:"requires_host_verification",Reason:"Supplied configuration fact matched; affected versions, effective permissions and exploitation preconditions are not independently verified"})}}
	sort.SliceStable(result,func(i,j int)bool{return result[i].Technique.Priority>result[j].Technique.Priority})
	return result
}
