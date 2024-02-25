#include "file_reader.h"
#include "tested_declarations.h"
#include "rdebug.h"



struct dir_entry_t *read_directory_entry(const char *filename){
    static FILE *file_ptr=NULL;

    if(filename != NULL){
        file_ptr = fopen(filename, "rb");
        if(file_ptr == NULL)
            return NULL;
    }
    struct dir_entry_read_t *ptr_dir_read = malloc(sizeof(struct dir_entry_read_t));
    if(ptr_dir_read == NULL)
        return NULL;
    int res;
    do{
        res = fread(ptr_dir_read, sizeof(struct dir_entry_read_t),1,file_ptr);
        if(res != 1) {
            fclose(file_ptr);
            free(ptr_dir_read);
            return NULL;
        }
    }
    while (ptr_dir_read->name[0] == (char)0xe5);


    if(ptr_dir_read->name[0] == 0x00){
        fclose(file_ptr);
        free(ptr_dir_read);
        return NULL;
    }

    struct dir_entry_t *ptr_dir_entry = malloc(sizeof(struct dir_entry_t));
    if(ptr_dir_entry == NULL){
        free(ptr_dir_read);
        return NULL;
    }

    memcpy(ptr_dir_entry->name,ptr_dir_read->name,8);
    if(isalnum(ptr_dir_entry->name[7]) || ptr_dir_entry->name[7] == '\''){
        if(isalnum(ptr_dir_read->extension[0])) {
            int i=8;
            ptr_dir_entry->name[i] = '.';
            i++;
            int j = 0;
            while (isalnum(ptr_dir_read->extension[j])) {
                ptr_dir_entry->name[i] = ptr_dir_read->extension[j];
                j++;
                i++;
            }
        }
        else
            ptr_dir_entry->name[8] = '\0';

    }
    for(int i=0;i<8;i++){
        if(!isalnum(ptr_dir_entry->name[i]) && ptr_dir_entry->name[i] != '\''){
            if(isalnum(ptr_dir_read->extension[0])){
                ptr_dir_entry->name[i] = '.';
                i++;
                int j=0;
                while (isalnum(ptr_dir_read->extension[j])){
                    ptr_dir_entry->name[i] = ptr_dir_read->extension[j];
                    j++;
                    i++;
                }
            }
            ptr_dir_entry->name[i] = '\0';
            break;
        }
    }

    ptr_dir_entry->creation_date.year = ptr_dir_read->creation_date.date_in_bytes.year + 1980;
    ptr_dir_entry->creation_date.month = ptr_dir_read->creation_date.date_in_bytes.month;
    ptr_dir_entry->creation_date.day = ptr_dir_read->creation_date.date_in_bytes.day;

    ptr_dir_entry->size = ptr_dir_read->size;

    ptr_dir_entry->creation_time.second = ptr_dir_read->creation_time.time_in_bytes.seconds;
    ptr_dir_entry->creation_time.hour = ptr_dir_read->creation_time.time_in_bytes.hours;
    ptr_dir_entry->creation_time.minute = ptr_dir_read->creation_time.time_in_bytes.minutes;

    ptr_dir_entry->is_archived = (ptr_dir_read->attributes & FAT_ATTRIB_ARCHIVE) ? 1 : 0;
    ptr_dir_entry->is_directory = (ptr_dir_read->attributes & FAT_ATTRIB_DIRECTORY) ? 1 : 0;
    ptr_dir_entry->is_hidden = (ptr_dir_read->attributes & FAT_ATTRIB_HIDDEN) ? 1 : 0;
    ptr_dir_entry->is_readonly = (ptr_dir_read->attributes & FAT_ATTRIB_READONLY) ? 1 : 0;
    ptr_dir_entry->is_system = (ptr_dir_read->attributes & FAT_ATTRIB_SYSTEM) ? 1 : 0;

    free(ptr_dir_read);
    return ptr_dir_entry;
}

struct clusters_chain_t *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster){
    if(buffer == NULL || size <= 0)
        return NULL;
    uint8_t *ptr = (uint8_t*)buffer;
    uint16_t value = first_cluster;
    int counter=0;
    while(value < 0xff8){
        int first_idx = (int)(value*1.5);
        int second_idx = first_idx + 1;

        int first_val = ptr[first_idx];
        int second_val = ptr[second_idx];
        if(value % 2 == 0){
            value = ((second_val & 0x0F) << 8) | first_val;
        }
        else if(value % 2 != 0){
            value = ((first_val & 0xF0) >> 4);
            value = value | (second_val << 4);
        }
        counter++;
    }
    struct clusters_chain_t* ret = malloc(sizeof(struct clusters_chain_t));
    if(ret == NULL)
        return NULL;
    ret->clusters = malloc(sizeof(uint16_t)*counter);
    if(ret->clusters == NULL){
        free(ret);
        return NULL;
    }
    counter=0;
    value = first_cluster;
    while(value < 0xff8){
        ret->clusters[counter] = value;
        counter++;
        int first_idx = (int)(value*1.5);
        int second_idx = first_idx + 1;

        int first_val = ptr[first_idx];
        int second_val = ptr[second_idx];
        if(value % 2 == 0){
            value = ((second_val & 0x0F) << 8) | first_val;
        }
        else if(value % 2 != 0){
            value = ((first_val & 0xF0) >> 4);
            value = value | (second_val << 4);
        }
    }
    ret->size = counter;
    return ret;
}


struct disk_t* disk_open_from_file(const char* volume_file_name){
    if(volume_file_name == NULL){
        errno = EFAULT;
        return NULL;
    }
    struct disk_t* disk = malloc(sizeof(struct disk_t));
    if(disk == NULL){
        errno = ENOMEM;
        return NULL;
    }
    disk->file_ptr = fopen(volume_file_name,"rb");
    if(disk->file_ptr == NULL){
        errno = ENOENT;
        free(disk);
        return NULL;
    }
    return disk;
}

int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read){
    if(pdisk == NULL || buffer == NULL || first_sector < 0 || sectors_to_read <= 0){
        errno = EFAULT;
        return -1;
    }
    fseek(pdisk->file_ptr,first_sector*512,SEEK_SET);
    int res = fread(buffer, 512, sectors_to_read, pdisk->file_ptr);

    if(res != sectors_to_read){
        errno = ERANGE;
        return -1;
    }
    return sectors_to_read;
}

int disk_close(struct disk_t* pdisk){
    if(pdisk == NULL){
        errno = EFAULT;
        return -1;
    }
    fclose(pdisk->file_ptr);
    free(pdisk);
    return 0;
}


struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector){
    if(pdisk == NULL){
        errno = EFAULT;
        return NULL;
    }
    struct volume_t* volume_ptr = malloc(sizeof(struct volume_t));
    volume_ptr->ptr_super = malloc(sizeof(fat_super_t));
    disk_read(pdisk,0,volume_ptr->ptr_super,1);

    if(volume_ptr->ptr_super->magic != 0xaa55){
        free(volume_ptr->ptr_super);
        free(volume_ptr);
        return NULL;
    }

    int bytes_per_fat = volume_ptr->ptr_super->bytes_per_sector * volume_ptr->ptr_super->sectors_per_fat;
    volume_ptr->fat = malloc(bytes_per_fat);
    volume_ptr->fat1_position = volume_ptr->ptr_super->reserved_sectors;
    disk_read(pdisk,volume_ptr->fat1_position,volume_ptr->fat,volume_ptr->ptr_super->sectors_per_fat);

    volume_ptr->ptr_disk = pdisk;
    volume_ptr->root_dir_sectors = ((sizeof(struct dir_entry_read_t)*volume_ptr->ptr_super->root_dir_capacity) + (volume_ptr->ptr_super->bytes_per_sector - 1))/volume_ptr->ptr_super->bytes_per_sector;
    volume_ptr->first_data_sector = volume_ptr->ptr_super->reserved_sectors + (volume_ptr->ptr_super->fat_count * volume_ptr->ptr_super->sectors_per_fat) + volume_ptr->root_dir_sectors;
    volume_ptr->total_sectors = (volume_ptr->ptr_super->logical_sectors16 == 0) ? volume_ptr->ptr_super->logical_sectors32 : volume_ptr->ptr_super->logical_sectors16;
    volume_ptr->data_sectors = volume_ptr->total_sectors - volume_ptr->first_data_sector;
    volume_ptr->total_clusters = volume_ptr->data_sectors/volume_ptr->ptr_super->sectors_per_cluster;
    volume_ptr->first_root_dir_sector = volume_ptr->first_data_sector - volume_ptr->root_dir_sectors;

    return volume_ptr;
}

int fat_close(struct volume_t* pvolume){
    if(pvolume == NULL){
        errno = EFAULT;
        return -1;
    }
    free(pvolume->ptr_super);
    free(pvolume->fat);
    free(pvolume);
    return 0;
}

struct file_t* file_open(struct volume_t* pvolume, const char* file_name){
    if(pvolume == NULL || file_name == NULL){
        errno = EFAULT;
        return NULL;
    }

    struct file_t* file = malloc(sizeof(struct file_t));
    if(file == NULL){
        errno = ENOMEM;
        return NULL;
    }

    struct dir_t* dir = dir_open(pvolume,"\\");

    struct dir_entry_t entry;
    uint16_t i=0;
    do {
        dir_read(dir, &entry);
        i++;
        if(i >= pvolume->ptr_super->root_dir_capacity){
            free(file);
            dir_close(dir);
            errno = ENOENT;
            return NULL;
        }
    } while ((strcmp(file_name,entry.name)) != 0);

    if(entry.size == 0){
        free(file);
        dir_close(dir);
        errno = EISDIR;
        return NULL;
    }

    file->size = entry.size;
    file->volume = pvolume;
    file->offset = 0;
    file->clusters_chain = get_chain_fat12(file->volume->fat,file->volume->ptr_super->sectors_per_fat*file->volume->ptr_super->bytes_per_sector,dir->first_cluster);
    file->current_cluster=0;

    dir_close(dir);

    return file;
}
int file_close(struct file_t* stream){
    if(stream == NULL){
        errno = EFAULT;
        return -1;
    }
    free(stream->clusters_chain->clusters);
    free(stream->clusters_chain);
    free(stream);
    return 0;

}
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream){
    if(ptr == NULL || stream == NULL){
        errno = EFAULT;
        return -1;
    }
    uint16_t bytes_per_sector = stream->volume->ptr_super->bytes_per_sector;
    uint16_t sectors_per_cluster = stream->volume->ptr_super->sectors_per_cluster;

    char* pt = malloc(sectors_per_cluster *  bytes_per_sector);
    if((size_t)stream->current_cluster*sectors_per_cluster *  bytes_per_sector + stream->offset + size  >= stream->size+1){
        if((size_t)stream->current_cluster*sectors_per_cluster *  bytes_per_sector + stream->offset +1  == stream->size) {
            disk_read(stream->volume->ptr_disk, stream->volume->first_data_sector +((stream->clusters_chain->clusters[stream->current_cluster] - 2) *sectors_per_cluster), pt, sectors_per_cluster);
            memcpy(ptr, pt + stream->offset, 1);
            if(size == 1 && nmemb == 1)
                return 1;
        }
        free(pt);
        return 0;
    }

    uint32_t bytes = size*nmemb;
    if(size*nmemb > stream->size)
        bytes = stream->size;
    int diff;
    int flag=0;
    int off=0;
    if(bytes < sectors_per_cluster *  bytes_per_sector){
        stream->offset+=bytes;
        if(stream->offset > sectors_per_cluster *  512){
           diff = stream->offset - sectors_per_cluster *  512;
           bytes = bytes - diff;
           flag=1;
            stream->offset-=(diff+bytes);
            off=bytes;
        }
        else
            stream->offset-=bytes;
        disk_read(stream->volume->ptr_disk,stream->volume->first_data_sector+((stream->clusters_chain->clusters[stream->current_cluster]-2)*sectors_per_cluster),pt,sectors_per_cluster);

        memcpy(ptr,pt+stream->offset,bytes);
        if(flag == 1){
            stream->offset+=bytes;
            bytes = diff;
            if(stream->offset >= sectors_per_cluster *  512){
                stream->current_cluster+=(stream->offset)/(sectors_per_cluster *  512);
                stream->offset-=(sectors_per_cluster *  512);
            }
            disk_read(stream->volume->ptr_disk,stream->volume->first_data_sector+((stream->clusters_chain->clusters[stream->current_cluster]-2)*sectors_per_cluster),pt,sectors_per_cluster);
            memcpy((char*)ptr+off,pt+stream->offset,bytes);
        }

    }
    else {
        uint32_t i;
        uint32_t read_bytes = 0;

        for (i = 0; i < stream->clusters_chain->size - 1; i++) {
            disk_read(stream->volume->ptr_disk, stream->volume->first_data_sector + ((stream->clusters_chain->clusters[i] - 2) * sectors_per_cluster), (char *) ptr + (i *(sectors_per_cluster*bytes_per_sector)),sectors_per_cluster);
            read_bytes += (sectors_per_cluster * 512);
        }

        disk_read(stream->volume->ptr_disk, stream->volume->first_data_sector +((stream->clusters_chain->clusters[i] - 2) *sectors_per_cluster), pt,sectors_per_cluster);
        memcpy((char *) ptr +(i * (sectors_per_cluster * bytes_per_sector)), pt,bytes - read_bytes);

    }

    free(pt);
    stream->offset+=bytes;
    if(stream->offset >= sectors_per_cluster *  512){
        stream->current_cluster+=(stream->offset)/(sectors_per_cluster *  512);
        stream->offset-=(sectors_per_cluster *  512);
    }
    if(size != 1)
        return nmemb;
    return bytes;
}
int32_t file_seek(struct file_t* stream, int32_t offset, int whence){
    if(stream == NULL){
        errno = EFAULT;
        return -1;
    }
    if(whence < 0 || whence > (int)stream->size){
        errno = EINVAL;
        return -1;
    }
    uint16_t sectors_per_cluster = stream->volume->ptr_super->sectors_per_cluster;
    uint16_t bytes_per_sector = stream->volume->ptr_super->bytes_per_sector;

    if(whence == SEEK_CUR){
        stream->offset+=offset;
    }
    else if(whence == SEEK_SET){
        stream->offset=offset;
    }
    else if(whence == SEEK_END){
        if(offset > 0){
            errno = ENXIO;
            return -1;
        }
        stream->offset=stream->size+offset;
    }

    if(stream->offset >= sectors_per_cluster *  512){
        stream->current_cluster+=(stream->offset)/(sectors_per_cluster *  512);
        stream->offset-=(sectors_per_cluster *  512)*stream->current_cluster;
        stream->offset=abs(stream->offset);
    }

    return stream->current_cluster*sectors_per_cluster*bytes_per_sector + stream->offset;

}

struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path){
    if(pvolume == NULL || dir_path == NULL){
        errno = EFAULT;
        return NULL;
    }
    if(strcmp(dir_path,"\\") != 0){
        errno = ENOENT;
        return NULL;
    }
    uint32_t offset = 0;
    struct dir_t* dir = malloc(sizeof(struct dir_t));
    if(dir == NULL){
        errno = ENOMEM;
        return NULL;
    }
    dir->volume = pvolume;
    dir->offset = offset;
    dir->current_cluster=0;
    return dir;
}
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry){
    if(pdir == NULL || pentry == NULL){
        errno = EFAULT;
        return -1;
    }

    char buff[1028];
    struct dir_entry_read_t *ptr_dir_read;

    do{
        disk_read(pdir->volume->ptr_disk,pdir->volume->first_root_dir_sector,buff,2);
        ptr_dir_read = (struct dir_entry_read_t *)(buff + pdir->offset);
        if(ptr_dir_read->name[0] != (char)0xe5 && isupper(ptr_dir_read->name[0]) == 0)
            return 1;
        pdir->offset+= sizeof(struct dir_entry_read_t);
        pdir->current_cluster++;
    }
    while (ptr_dir_read->name[0] == (char)0xe5);

    pdir->first_cluster = ptr_dir_read->last_chain_index;

    pentry->is_archived = (ptr_dir_read->attributes & FAT_ATTRIB_ARCHIVE) ? 1 : 0;
    pentry->is_directory = (ptr_dir_read->attributes & FAT_ATTRIB_DIRECTORY) ? 1 : 0;
    pentry->is_hidden = (ptr_dir_read->attributes & FAT_ATTRIB_HIDDEN) ? 1 : 0;
    pentry->is_readonly = (ptr_dir_read->attributes & FAT_ATTRIB_READONLY) ? 1 : 0;
    pentry->is_system = (ptr_dir_read->attributes & FAT_ATTRIB_SYSTEM) ? 1 : 0;

    pentry->size = ptr_dir_read->size;


    memcpy(pentry->name,ptr_dir_read->name,8);
    if(isalnum(pentry->name[7]) || pentry->name[7] == '\''){
        if(isalnum(ptr_dir_read->extension[0])) {
            int i=8;
            pentry->name[i] = '.';
            i++;
            int j = 0;
            while (isalnum(ptr_dir_read->extension[j])) {
                pentry->name[i] = ptr_dir_read->extension[j];
                j++;
                i++;
            }
        }
        else
            pentry->name[8] = '\0';

    }
    for(int i=0;i<8;i++){
        if(!isalnum(pentry->name[i]) && pentry->name[i] != '\''){
            if(isalnum(ptr_dir_read->extension[0])){
                pentry->name[i] = '.';
                i++;
                int j=0;
                while (isalnum(ptr_dir_read->extension[j])){
                    pentry->name[i] = ptr_dir_read->extension[j];
                    j++;
                    i++;
                }
            }
            pentry->name[i] = '\0';
            break;
        }
    }
    pentry->name[12] = '\0';

    return 0;


}
int dir_close(struct dir_t* pdir){
    if(pdir == NULL){
        errno = EFAULT;
        return -1;
    }
    free(pdir);
    return 0;

}