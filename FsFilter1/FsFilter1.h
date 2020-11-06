#define MESSAGE_TOTAL_SIZE_WITH_HEADER 1024
// FILTER_MESSAGE_HEADER size is 16
#define MESSAGE_TOTAL_SIZE (MESSAGE_TOTAL_SIZE_WITH_HEADER -  16)
#define MESSAGE_STRUCT_SIZE (MESSAGE_TOTAL_SIZE - sizeof(unsigned int))
#define MESSAGE_FILE_BUFFER_SIZE (MESSAGE_STRUCT_SIZE - sizeof(unsigned short))
#define MESSAGE_FILE_BUFFER_WSIZE (MESSAGE_FILE_BUFFER_SIZE / 2)

enum MessageKind {
    MessageKind_Invalid,
    MessageKind_Empty,
    MessageKind_File,
    MessageKind_Process
};

struct EmptyMessage {
    unsigned char Buffer[MESSAGE_STRUCT_SIZE];
};

struct FileMessage {
    unsigned short WideLength;
    unsigned short Buffer[MESSAGE_FILE_BUFFER_WSIZE];
};

struct ProcessMessage {
    unsigned long ProcessId;
    unsigned long ParentId;
    unsigned int Create;
};


struct Message {
    int Kind;
    union {
        struct EmptyMessage invalid;
        struct EmptyMessage empty;
        struct FileMessage file;
        struct ProcessMessage process;
    } Data;
};

static_assert (sizeof(struct EmptyMessage) == MESSAGE_STRUCT_SIZE, "EmptyMessage is wrong size");
static_assert (sizeof(struct FileMessage) == MESSAGE_STRUCT_SIZE, "FileMessage is wrong size");
static_assert (sizeof(struct ProcessMessage) <= MESSAGE_STRUCT_SIZE, "ProcessMessage is wrong size");
static_assert (sizeof(struct Message) == MESSAGE_TOTAL_SIZE, "Message is wrong size");

#define ERROR_WITH_SIZE(OBJ) void blah() { switch (1) { case OBJ: case OBJ: break; } }
// ERROR_WITH_SIZE(sizeof(struct ProcessMessage))
// ERROR_WITH_SIZE(sizeof(unsigned int))
// ERROR_WITH_SIZE(MESSAGE_STRUCT_SIZE)