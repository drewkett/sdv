#define MESSAGE_TOTAL_SIZE_WITH_HEADER 1024
// FILTER_MESSAGE_HEADER size is 16
#define MESSAGE_TOTAL_SIZE (MESSAGE_TOTAL_SIZE_WITH_HEADER -  16)
#define MESSAGE_STRUCT_SIZE (MESSAGE_TOTAL_SIZE - sizeof(int))

enum MessageKind {
    MessageKind_Invalid,
    MessageKind_Empty,
    MessageKind_File,
    MessageKind_Process,
    MessageKind_Image
};

#define MajorFunction_Create 0
#define MajorFunction_Read 3
#define MajorFunction_Write 4

struct EmptyMessage {
    unsigned char Buffer[MESSAGE_STRUCT_SIZE];
};

struct FileMessageAttr {
    unsigned long ProcessId;
    unsigned char MajorFunction;
    unsigned short WideLength;
};

#define MESSAGE_FILE_BUFFER_SIZE (MESSAGE_STRUCT_SIZE - sizeof(struct FileMessageAttr))
#define MESSAGE_FILE_BUFFER_WSIZE (MESSAGE_FILE_BUFFER_SIZE / 2)

struct FileMessage {
    struct FileMessageAttr Attr;
    unsigned short Buffer[MESSAGE_FILE_BUFFER_WSIZE];
};

struct ProcessMessage {
    unsigned long ProcessId;
    unsigned long ParentId;
    unsigned int Create;
};

#define MESSAGE_IMAGE_BUFFER_SIZE (MESSAGE_STRUCT_SIZE - sizeof(struct ImageMessageAttr))
#define MESSAGE_IMAGE_BUFFER_WSIZE (MESSAGE_IMAGE_BUFFER_SIZE / 2)

struct ImageMessageAttr {
    unsigned long ProcessId;
    unsigned short WideLength;
};

struct ImageMessage {
    struct ImageMessageAttr Attr;
    unsigned short Buffer[MESSAGE_IMAGE_BUFFER_WSIZE];
};

struct Message {
    int Kind;
    union {
        struct EmptyMessage Invalid;
        struct EmptyMessage Empty;
        struct FileMessage File;
        struct ProcessMessage Process;
        struct ImageMessage Image;
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