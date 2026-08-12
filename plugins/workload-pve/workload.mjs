const string = (options = {}) => Object.freeze({ type: "string", ...options });
const integer = (options = {}) => Object.freeze({ type: "integer", ...options });
const boolean = () => Object.freeze({ type: "boolean" });
const literal = (value) => Object.freeze({ type: "string", const: value });
const object = (properties, required = Object.keys(properties)) => Object.freeze({
  type: "object",
  properties: Object.freeze(properties),
  required: Object.freeze(required),
  additionalProperties: false,
});
const union = (...anyOf) => Object.freeze({ anyOf: Object.freeze(anyOf) });

const machineId = string({ minLength: 8, maxLength: 160 });
const targetId = string({ minLength: 8, maxLength: 160 });
const node = string({ minLength: 1, maxLength: 64 });
const storage = string({ minLength: 1, maxLength: 64 });
const guestType = Object.freeze({ type: "string", enum: ["qemu", "lxc"] });
const vmid = integer({ minimum: 100, maximum: 999999999 });
const snapshot = string({ minLength: 1, maxLength: 64 });
const recoveryOfChangeId = string({
  minLength: 19,
  maxLength: 160,
});
const scope = Object.freeze({ machineId, targetId });
const recoveryObject = (properties, required = Object.keys(properties)) => object(
  { ...properties, recoveryOfChangeId },
  required,
);

const tools = Object.freeze([
  Object.freeze({
    name: "ops_pve_backup_prepare",
    label: "Prepare PVE guest backup",
    description: "Prepare one typed guest backup through the PVE broker. Only an exact pve.guest.backup standing scope may authorize an ordinary backup. Set recoveryOfChangeId only to recover the same locked VMID from a RECOVERY_REQUIRED parent; that path is never standing-authorized.",
    capability: "pve.backup",
    parameters: recoveryObject({ ...scope, node, guestType, vmid, storage }),
    providers: Object.freeze(["pve.backup"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_pve_cluster_inspect",
    label: "Inspect PVE cluster",
    description: "Read the bounded Proxmox cluster status through the typed PVE inspection protocol.",
    capability: "pve.cluster.inspect",
    parameters: object(scope),
    providers: Object.freeze(["pve.cluster.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_pve_guest_inspect",
    label: "Inspect PVE guest",
    description: "Read current status for one explicitly selected QEMU or LXC guest.",
    capability: "pve.guest.inspect",
    parameters: object({ ...scope, node, guestType, vmid }),
    providers: Object.freeze(["pve.guest.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_pve_guest_lifecycle_prepare",
    label: "Prepare PVE guest lifecycle action",
    description: "Prepare one typed start, shutdown, stop, or reboot action. Only start or shutdown may consume an exact matching standing scope; stop and reboot always require separate human approval. An optional recoveryOfChangeId binds a separate recovery child to the same unresolved VMID and always requires local approval.",
    capability: "pve.guest.lifecycle",
    parameters: recoveryObject({
      ...scope,
      node,
      guestType,
      vmid,
      action: Object.freeze({ type: "string", enum: ["start", "shutdown", "stop", "reboot"] }),
    }),
    providers: Object.freeze(["pve.guest.lifecycle"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_pve_guest_migrate_prepare",
    label: "Prepare PVE guest migration",
    description: "Prepare a typed guest migration with explicit source, target, and mode flags. Migration is never standing-authorized and always requires separate human approval.",
    capability: "pve.guest.migrate",
    parameters: recoveryObject({
      ...scope,
      node,
      guestType,
      vmid,
      targetNode: node,
      online: boolean(),
      restart: boolean(),
      withLocalDisks: boolean(),
    }),
    providers: Object.freeze(["pve.guest.migrate"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_pve_guest_restore_prepare",
    label: "Prepare PVE guest restore",
    description: "Prepare a typed restore from one bounded PVE backup volume into the selected guest. Restore is never standing-authorized and always requires separate human approval.",
    capability: "pve.guest.restore",
    parameters: recoveryObject({
      ...scope,
      node,
      guestType,
      vmid,
      backupVolume: string({ minLength: 24, maxLength: 256 }),
      storage,
    }),
    providers: Object.freeze(["pve.guest.restore"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_pve_node_inspect",
    label: "Inspect PVE node",
    description: "Read bounded status for one explicitly selected Proxmox node.",
    capability: "pve.node.inspect",
    parameters: object({ ...scope, node }),
    providers: Object.freeze(["pve.node.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_pve_snapshot_prepare",
    label: "Prepare PVE snapshot action",
    description: "Prepare a typed snapshot create, delete, or rollback. Only create may consume an exact pve.snapshot.create standing scope; delete and rollback require backup storage and always require separate human approval.",
    capability: "pve.snapshot.manage",
    parameters: union(
      recoveryObject(
        {
          ...scope,
          action: literal("create"),
          node,
          guestType,
          vmid,
          snapshot,
          description: string({ maxLength: 1024 }),
        },
        ["machineId", "targetId", "action", "node", "guestType", "vmid", "snapshot"],
      ),
      recoveryObject({
        ...scope,
        action: Object.freeze({ type: "string", enum: ["delete", "rollback"] }),
        node,
        guestType,
        vmid,
        snapshot,
        backupStorage: storage,
      }),
    ),
    providers: Object.freeze(["pve.snapshot.manage"]),
    executionMode: "sequential",
  }),
  Object.freeze({
    name: "ops_pve_storage_inspect",
    label: "Inspect PVE storage",
    description: "Read bounded status for one explicitly selected node storage.",
    capability: "pve.storage.inspect",
    parameters: object({ ...scope, node, storage }),
    providers: Object.freeze(["pve.storage.inspect"]),
    executionMode: "parallel",
  }),
  Object.freeze({
    name: "ops_pve_task_inspect",
    label: "Inspect PVE task",
    description: "Read bounded status for one PVE UPID bound to the selected node.",
    capability: "pve.task.inspect",
    parameters: object({ ...scope, node, upid: string({ minLength: 16, maxLength: 512 }) }),
    providers: Object.freeze(["pve.task.inspect"]),
    executionMode: "parallel",
  }),
]);

export const workload = Object.freeze({
  apiVersion: "agentd.workload/v1",
  tools,
  async invoke(request, api) {
    switch (request.tool) {
      case "ops_pve_backup_prepare": {
        const { machineId: selectedMachine, targetId: selectedTarget, ...operation } = request.input;
        return await api.call("pve.backup", {
          machineId: selectedMachine,
          targetId: selectedTarget,
          operation: { kind: "pve.guest.backup", ...operation },
        });
      }
      case "ops_pve_cluster_inspect":
        return await api.call("pve.cluster.inspect", { ...request.input, operation: "cluster_status" });
      case "ops_pve_guest_inspect":
        return await api.call("pve.guest.inspect", { ...request.input, operation: "guest_status" });
      case "ops_pve_guest_lifecycle_prepare": {
        const { machineId: selectedMachine, targetId: selectedTarget, ...operation } = request.input;
        return await api.call("pve.guest.lifecycle", {
          machineId: selectedMachine,
          targetId: selectedTarget,
          operation: { kind: "pve.guest.action", ...operation },
        });
      }
      case "ops_pve_guest_migrate_prepare": {
        const { machineId: selectedMachine, targetId: selectedTarget, ...operation } = request.input;
        return await api.call("pve.guest.migrate", {
          machineId: selectedMachine,
          targetId: selectedTarget,
          operation: { kind: "pve.guest.migrate", ...operation },
        });
      }
      case "ops_pve_guest_restore_prepare": {
        const { machineId: selectedMachine, targetId: selectedTarget, ...operation } = request.input;
        return await api.call("pve.guest.restore", {
          machineId: selectedMachine,
          targetId: selectedTarget,
          operation: { kind: "pve.guest.restore", ...operation },
        });
      }
      case "ops_pve_node_inspect":
        return await api.call("pve.node.inspect", { ...request.input, operation: "node_status" });
      case "ops_pve_snapshot_prepare": {
        const { machineId: selectedMachine, targetId: selectedTarget, action, ...operation } = request.input;
        return await api.call("pve.snapshot.manage", {
          machineId: selectedMachine,
          targetId: selectedTarget,
          operation: { kind: `pve.snapshot.${action}`, ...operation },
        });
      }
      case "ops_pve_storage_inspect":
        return await api.call("pve.storage.inspect", { ...request.input, operation: "storage_status" });
      case "ops_pve_task_inspect":
        return await api.call("pve.task.inspect", { ...request.input, operation: "task_status" });
      default:
        throw new Error("workload.pve received an unknown tool");
    }
  },
});
