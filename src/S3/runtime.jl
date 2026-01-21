mutable struct RuntimeState
    initialized::Bool
    refcount::Int
    allocator::Ptr{Libaws_c_s3.aws_allocator}
end

const RUNTIME_LOCK = ReentrantLock()
const RUNTIME_STATE = RuntimeState(false, 0, Ptr{Libaws_c_s3.aws_allocator}(C_NULL))
const RUNTIME_ATEXIT_REGISTERED = Ref(false)

function init_runtime!(alloc::AllocPtr)::Nothing
    aws_common_library_init(alloc)
    io_init(alloc)
    http_init(alloc)
    auth_init(alloc)
    Libaws_c_s3.aws_s3_library_init(alloc)
    return nothing
end

function runtime_cleanup!()::Nothing
    Libaws_c_s3.aws_s3_library_clean_up()
    auth_cleanup()
    http_cleanup()
    io_cleanup()
    common_cleanup()
    return nothing
end

function register_runtime_atexit!()::Nothing
    if !RUNTIME_ATEXIT_REGISTERED[]
        atexit(() -> force_shutdown_runtime!())
        RUNTIME_ATEXIT_REGISTERED[] = true
    end
    return nothing
end

function ensure_runtime!(alloc::AllocPtr=default_allocator())::AllocPtr
    lock(RUNTIME_LOCK)
    try
        if !RUNTIME_STATE.initialized
            init_runtime!(alloc)
            RUNTIME_STATE.initialized = true
            RUNTIME_STATE.refcount = 1
            RUNTIME_STATE.allocator = alloc
            register_runtime_atexit!()
        else
            alloc != RUNTIME_STATE.allocator && error("ensure_runtime! called with different allocator")
            RUNTIME_STATE.refcount += 1
        end
        return RUNTIME_STATE.allocator
    finally
        unlock(RUNTIME_LOCK)
    end
end

function force_shutdown_runtime!()::Nothing
    do_cleanup = false
    lock(RUNTIME_LOCK)
    try
        if RUNTIME_STATE.initialized
            do_cleanup = true
            RUNTIME_STATE.initialized = false
            RUNTIME_STATE.refcount = 0
            RUNTIME_STATE.allocator = Ptr{Libaws_c_s3.aws_allocator}(C_NULL)
        end
    finally
        unlock(RUNTIME_LOCK)
    end
    do_cleanup && runtime_cleanup!()
    return nothing
end

function shutdown_runtime!()::Nothing
    do_cleanup = false
    lock(RUNTIME_LOCK)
    try
        !RUNTIME_STATE.initialized && return nothing
        RUNTIME_STATE.refcount = max(0, RUNTIME_STATE.refcount - 1)
        if RUNTIME_STATE.refcount == 0
            do_cleanup = true
            RUNTIME_STATE.initialized = false
            RUNTIME_STATE.allocator = Ptr{Libaws_c_s3.aws_allocator}(C_NULL)
        end
    finally
        unlock(RUNTIME_LOCK)
    end
    do_cleanup && runtime_cleanup!()
    return nothing
end