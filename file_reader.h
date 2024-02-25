#ifndef FAT_PROJECT_FILE_READER_H
#define FAT_PROJECT_FILE_READER_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

struct creation_date_t{
    int day;
    int month;
    int year;
};

struct creation_time_t{
    int hour;
    int minute;
    int second;
};

struct dir_entry_t{
    char name[13];
    size_t size;
    int is_archived;
    int is_readonly;
    int is_system;
    int is_hidden;
    int is_directory;
    struct creation_date_t creation_date;
    struct creation_time_t creation_time;
};

enum fat_attributes_t{
    FAT_ATTRIB_READONLY = 0x01,
    FAT_ATTRIB_HIDDEN = 0x02,
    FAT_ATTRIB_SYSTEM = 0x04,
    FAT_ATTRIB_VOLUME = 0x08,
    FAT_ATTRIB_DIRECTORY = 0x10,
    FAT_ATTRIB_ARCHIVE = 0x20
}__attribute__((packed));

typedef union fat_time_t{
    uint16_t full_time;
    struct time_in_bytes_t{
        unsigned int seconds: 5;
        unsigned int minutes: 6;
        unsigned int hours: 5;
    }__attribute__((packed))time_in_bytes;
}fat_time_t;



typedef union fat_date_t{
    uint16_t full_date;
    struct date_in_bytes_t {
        unsigned int day: 5;
        unsigned int month: 4;
        unsigned int year: 7;
    }__attribute__((packed)) date_in_bytes;
}fat_date_t;

struct dir_entry_read_t{
    char name[8];
    char extension[3];
    enum fat_attributes_t attributes;
    uint8_t reserved;
    uint8_t creation_time_ms;
    fat_time_t creation_time;
    fat_date_t creation_date;
    fat_time_t last_acces_time;
    uint16_t high_chain_index;
    fat_time_t last_modification_time;
    fat_date_t last_modification_date;
    uint16_t last_chain_index;
    uint32_t size;
}__attribute__((packed));


typedef struct fat_super_t {
    uint8_t  jump_code[3];
    char     oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors; // sektory zarezerwowane nieużywane w ss
    uint8_t  fat_count; // ilość fatow
    uint16_t root_dir_capacity; // ilosc wpisow w katalogu głownym
    uint16_t logical_sectors16;//sectors in volume
    uint8_t  media_type;
    uint16_t sectors_per_fat;
    uint16_t chs_sectors_per_track;
    uint16_t chs_tracks_per_cylinder;
    uint32_t hidden_sectors;
    uint32_t logical_sectors32;
    uint8_t  media_id;
    uint8_t  chs_head;
    uint8_t  ext_bpb_signature;
    uint32_t serial_number;
    char     volume_label[11];
    char     fsid[8];
    uint8_t  boot_code[448];
    uint16_t magic; // 0xaa55
}__attribute__((packed)) fat_super_t;



struct disk_t{
    FILE *file_ptr;
};


struct disk_t* disk_open_from_file(const char* volume_file_name);
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);
int disk_close(struct disk_t* pdisk);


struct volume_t{
    fat_super_t* ptr_super;
    struct disk_t *ptr_disk;

    uint8_t *fat;

    uint16_t fat1_position;
    uint16_t root_dir_sectors;
    uint32_t first_data_sector;
    uint32_t total_sectors; // wszytkie sektory w woluminie
    uint32_t data_sectors;
    uint32_t total_clusters;
    uint32_t first_root_dir_sector;
};
struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector);
int fat_close(struct volume_t* pvolume);


struct file_t{
    struct volume_t *volume;
    struct clusters_chain_t* clusters_chain;
    int offset;
    int current_cluster;
    size_t size;
};
struct file_t* file_open(struct volume_t* pvolume, const char* file_name);
int file_close(struct file_t* stream);
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);
int32_t file_seek(struct file_t* stream, int32_t offset, int whence);


struct dir_t{
    struct volume_t *volume;
    int offset;
    int current_cluster;
    int first_cluster;

};
struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path);
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry);
int dir_close(struct dir_t* pdir);



struct dir_entry_t *read_directory_entry(const char *filename);


struct clusters_chain_t{
    uint16_t *clusters;
    size_t size;
};

struct clusters_chain_t *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster);

#endif //FAT_PROJECT_FILE_READER_H