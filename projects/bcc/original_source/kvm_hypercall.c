#define EXIT_REASON 18
BPF_HASH(start, u8, u8);

TRACEPOINT_PROBE(kvm, kvm_exit) {
    u8 e = EXIT_REASON;
    u8 one = 1;
    if (args->exit_reason == EXIT_REASON) {
        bpf_trace_printk("KVM_EXIT exit_reason : %d\\n", args->exit_reason);
        start.update(&e, &one);
    }
    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_entry) {
    u8 e = EXIT_REASON;
    u8 zero = 0;
    u8 *s = start.lookup(&e);
    if (s != NULL && *s == 1) {
        bpf_trace_printk("KVM_ENTRY vcpu_id : %u\\n", args->vcpu_id);
        start.update(&e, &zero);
    }
    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_hypercall) {
    u8 e = EXIT_REASON;
    u8 zero = 0;
    u8 *s = start.lookup(&e);
    if (s != NULL && *s == 1) {
        bpf_trace_printk("HYPERCALL nr : %d\\n", args->nr);
    }
    return 0;
};
