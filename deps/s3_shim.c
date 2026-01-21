#include <aws/s3/s3_client.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/byte_buf.h>

struct s3_jl_result {
    struct aws_byte_buf body;
    int status;
    int error_code;
};

struct s3_jl_ctx {
    struct s3_jl_result *res;
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    bool done;
};

static int s3_jl_body_cb(
    struct aws_s3_meta_request *meta_request,
    const struct aws_byte_cursor *body,
    uint64_t range_start,
    void *user_data) {

    (void)meta_request;
    (void)range_start;

    struct s3_jl_ctx *ctx = (struct s3_jl_ctx *)user_data;
    aws_mutex_lock(&ctx->mutex);
    aws_byte_buf_append_dynamic(&ctx->res->body, body);
    aws_mutex_unlock(&ctx->mutex);
    return AWS_OP_SUCCESS;
}

static void s3_jl_finish_cb(
    struct aws_s3_meta_request *meta_request,
    const struct aws_s3_meta_request_result *result,
    void *user_data) {

    (void)meta_request;
    struct s3_jl_ctx *ctx = (struct s3_jl_ctx *)user_data;
    aws_mutex_lock(&ctx->mutex);
    ctx->res->status = result->response_status;
    ctx->res->error_code = result->error_code;
    ctx->done = true;
    aws_condition_variable_notify_one(&ctx->cv);
    aws_mutex_unlock(&ctx->mutex);
}

AWS_S3_API
int s3_jl_make_request(
    struct aws_allocator *allocator,
    struct aws_s3_client *client,
    struct aws_s3_meta_request_options *options,
    struct s3_jl_result *out_result) {

    if (!allocator || !client || !options || !out_result) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    struct s3_jl_ctx ctx;
    ctx.res = out_result;
    ctx.done = false;
    aws_mutex_init(&ctx.mutex);
    aws_condition_variable_init(&ctx.cv);

    aws_byte_buf_init(&out_result->body, allocator, 0);
    out_result->status = 0;
    out_result->error_code = 0;

    options->body_callback = s3_jl_body_cb;
    options->finish_callback = s3_jl_finish_cb;
    options->user_data = &ctx;

    struct aws_s3_meta_request *meta = aws_s3_client_make_meta_request(client, options);
    if (!meta) {
        int err = aws_last_error();
        aws_condition_variable_clean_up(&ctx.cv);
        aws_mutex_clean_up(&ctx.mutex);
        return err;
    }

    aws_mutex_lock(&ctx.mutex);
    while (!ctx.done) {
        aws_condition_variable_wait(&ctx.cv, &ctx.mutex);
    }
    aws_mutex_unlock(&ctx.mutex);

    aws_s3_meta_request_release(meta);
    aws_condition_variable_clean_up(&ctx.cv);
    aws_mutex_clean_up(&ctx.mutex);
    return AWS_ERROR_SUCCESS;
}

AWS_S3_API
void s3_jl_result_clean_up(struct s3_jl_result *result) {
    if (result) {
        aws_byte_buf_clean_up(&result->body);
    }
}
