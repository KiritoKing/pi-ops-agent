import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function repositoryFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

describe("BotMux host compatibility guard", () => {
  it("rejects observed restricted-userns AppArmor chains before every setup mutation", () => {
    const setup = repositoryFile("scripts/setup-botmux.sh");
    const guardStart = setup.indexOf(
      "reject_unsupported_restricted_userns_botmux_runtime() {",
    );
    const guardEnd = setup.indexOf(
      "\n}\n\nif ! reject_unsupported_restricted_userns_botmux_runtime",
      guardStart,
    );
    const guardCall = setup.indexOf(
      "if ! reject_unsupported_restricted_userns_botmux_runtime; then",
    );

    expect(guardStart).toBeGreaterThan(0);
    expect(guardEnd).toBeGreaterThan(guardStart);
    expect(guardCall).toBeGreaterThan(guardEnd);
    const guard = setup.slice(guardStart, guardEnd);

    expect(setup).toContain('readonly OS_RELEASE_PATH="/etc/os-release"');
    expect(setup).toContain(
      'readonly APPARMOR_ENABLED_PATH="/sys/module/apparmor/parameters/enabled"',
    );
    expect(setup).toContain(
      'readonly APPARMOR_RESTRICT_USERNS_PATH="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"',
    );
    expect(guard).toContain("/usr/bin/stat -Lc '%s'");
    expect(guard).toContain("os_release_size > MAX_OS_RELEASE_BYTES");
    expect(guard).toContain('/usr/bin/awk \'');
    expect(guard).toContain("id_count != 1 || version_count > 1 || invalid != 0");
    expect(guard).toContain('print "ubuntu-24.04"');
    expect(guard).toContain('print "other"');
    expect(guard).toContain('/usr/bin/head -c 8');
    expect(guard).toContain("other) ;;");
    expect(guard).toContain("ubuntu-24.04) noble_host=true ;;");
    expect(guard).toContain('|| "${noble_host}" == true');
    expect(guard).toContain("0) return 0 ;;");
    expect(guard).toContain("N|n) return 0 ;;");
    expect(guard).toContain("Y|y) ;;");
    expect(guard).toContain("could not parse unambiguous host OS release evidence");
    expect(guard).toContain("could not read the host restricted-userns state");
    expect(guard).toContain("could not read the host AppArmor state");
    expect(guard).toContain("received an invalid host restricted-userns state");
    expect(guard).toContain("received an invalid host AppArmor state");
    expect(guard).not.toContain("]] || return 0");
    expect(guard).toContain("including Ubuntu 24.04 Noble");
    expect(guard).toContain("refusing before any wrapper/config mutation, hardener, or restart");

    for (const forbidden of [
      "apparmor_parser", "sysctl ", "systemctl ", "install ", "runuser ",
    ]) {
      expect(guard).not.toContain(forbidden);
    }

    for (const laterAction of [
      'runuser_command="$(find_fixed_command',
      'setup_scratch="$(mktemp -d',
      '"${pluginctl_command}" current',
      "install -d -o root -g root -m 0755 /opt/pi-ops-agent/botmux-bin",
      'run_as_botmux "${node_command}" "${botmux_setup_runner}"',
    ]) {
      expect(setup.indexOf(laterAction), laterAction).toBeGreaterThan(guardCall);
    }
  });

  it("does not attach the bwrap setup profile to the BotMux main service", () => {
    const setup = repositoryFile("scripts/setup-botmux.sh");
    const dropIn = repositoryFile("config/botmux-systemd-dropin.conf");

    expect(setup).not.toContain("AppArmorProfile=");
    expect(dropIn).not.toContain("AppArmorProfile=");
    expect(setup).not.toContain("configure-noble-bwrap-apparmor.sh");
  });
});
