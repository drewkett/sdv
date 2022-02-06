// This is a hard coded total message size for the struct that is passed
// between the mini-filter and the userspace code
#define MESSAGE_WITH_HEADER_SIZE 1024
// FILTER_MESSAGE_HEADER size is 16
#define MESSAGE_SIZE (MESSAGE_WITH_HEADER_SIZE -  16)
// The message kind tag is an int
#define MESSAGE_PAYLOAD_SIZE (MESSAGE_SIZE - sizeof(int))

enum MessageKind {
    MessageKind_Invalid,
    MessageKind_Empty,
    MessageKind_File,
    MessageKind_Process,
    MessageKind_Image
};

// These map to IRP_MJ_* constants and are translated to an enum MajorFunction in the rust code
#define MajorFunction_Create 0
#define MajorFunction_Close 2
#define MajorFunction_Read 3
#define MajorFunction_Write 4
#define MajorFunction_SetInfo 6
#define MajorFunction_Cleanup 18

struct EmptyMessage {
    unsigned char Buffer[MESSAGE_PAYLOAD_SIZE];
};

struct FileMessageAttr {
    unsigned long ProcessId;
    unsigned char MajorFunction;
    unsigned short WideLength;
};

#define MESSAGE_FILE_BUFFER_SIZE (MESSAGE_PAYLOAD_SIZE - sizeof(struct FileMessageAttr))
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

#define MESSAGE_IMAGE_BUFFER_SIZE (MESSAGE_PAYLOAD_SIZE - sizeof(struct ImageMessageAttr))
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

// Compile time checks that the message payload sizes fit within MESSAGE_PAYLOAD_SIZE
static_assert (sizeof(struct EmptyMessage) == MESSAGE_PAYLOAD_SIZE, "EmptyMessage is wrong size");
static_assert (sizeof(struct FileMessage) == MESSAGE_PAYLOAD_SIZE, "FileMessage is wrong size");
static_assert (sizeof(struct ProcessMessage) <= MESSAGE_PAYLOAD_SIZE, "ProcessMessage is wrong size");
static_assert (sizeof(struct Message) == MESSAGE_SIZE, "Message is wrong size");
