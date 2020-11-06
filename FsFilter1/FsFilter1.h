#define MESSAGE_TOTAL_SIZE_WITH_HEADER 1024
// FILTER_MESSAGE_HEADER size is 16
#define MESSAGE_TOTAL_SIZE (MESSAGE_TOTAL_SIZE_WITH_HEADER -  16)
#define MESSAGE_STRUCT_SIZE (MESSAGE_TOTAL_SIZE - sizeof(unsigned short))
#define MESSAGE_FILE_BUFFER_SIZE (MESSAGE_STRUCT_SIZE - sizeof(unsigned short))
#define MESSAGE_FILE_BUFFER_WSIZE (MESSAGE_FILE_BUFFER_SIZE / 2)

struct EmptyMessage {
    unsigned char Buffer[MESSAGE_STRUCT_SIZE];
};

struct FileMessage {
    unsigned short WideLength;
    unsigned short Buffer[MESSAGE_FILE_BUFFER_WSIZE];
};


struct Message {
    unsigned short Kind;
    union {
        struct EmptyMessage empty;
        struct FileMessage file;
    } Data;
};

static_assert (sizeof(struct EmptyMessage) == MESSAGE_STRUCT_SIZE, "EmptyMessage is wrong size");
static_assert (sizeof(struct FileMessage) == MESSAGE_STRUCT_SIZE, "FileMessage is wrong size");
static_assert (sizeof(struct Message) == MESSAGE_TOTAL_SIZE, "Message is wrong size");

#define ERROR_WITH_SIZE(OBJ) void blah() { switch (1) { case OBJ: case OBJ: break; } }
// ERROR_WITH_SIZE(sizeof(struct Message))