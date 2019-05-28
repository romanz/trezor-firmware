if not __debug__:
    from trezor.utils import halt

    halt("debug mode inactive")

if __debug__:
    from trezor import config, loop, utils, wire
    from trezor.messages import MessageType
    from trezor.wire import register, protobuf_workflow

    reset_internal_entropy = None
    reset_current_words = None
    reset_word_index = None

    confirm_signal = loop.signal()
    swipe_signal = loop.signal()
    input_signal = loop.signal()

    async def dispatch_DebugLinkDecision(ctx, msg):
        from trezor.ui import confirm, swipe

        if msg.yes_no is not None:
            confirm_signal.send(confirm.CONFIRMED if msg.yes_no else confirm.CANCELLED)
        if msg.up_down is not None:
            swipe_signal.send(swipe.SWIPE_DOWN if msg.up_down else swipe.SWIPE_UP)
        if msg.input is not None:
            input_signal.send(msg.input)

    async def dispatch_DebugLinkGetState(ctx, msg):
        from trezor.messages.DebugLinkState import DebugLinkState
        from apps.common import storage, mnemonic

        m = DebugLinkState()
        m.mnemonic_secret, m.mnemonic_type = mnemonic.get()
        m.passphrase_protection = storage.has_passphrase()
        m.reset_word_pos = reset_word_index
        m.reset_entropy = reset_internal_entropy
        if reset_current_words:
            m.reset_word = " ".join(reset_current_words)
        return m

    async def dispatch_DebugLinkAllocateHeap(ctx, msg):
        from trezor.messages.Success import Success
        import gc
        gc.collect()
        mem_free = gc.mem_free()
        mem_alloc = gc.mem_alloc()

        buffers = []
        for i, size in enumerate(msg.sizes):
            try:
                buffers.append(bytearray(size))
            except MemoryError as e:
                raise wire.ProcessError('Failed allocating {}B (#{})'.format(size, i))

        total_size = sum(len(b) for b in buffers)
        del buffers
        return Success('Allocated {}B (starting with {}B free, {}B allocated)'.format(total_size, mem_free, mem_alloc))

    def boot():
        # wipe storage when debug build is used on real hardware
        if not utils.EMULATOR:
            config.wipe()

        register(
            MessageType.DebugLinkDecision, protobuf_workflow, dispatch_DebugLinkDecision
        )
        register(
            MessageType.DebugLinkGetState, protobuf_workflow, dispatch_DebugLinkGetState
        )
        register(
            MessageType.DebugLinkAllocateHeap, protobuf_workflow, dispatch_DebugLinkAllocateHeap
        )
