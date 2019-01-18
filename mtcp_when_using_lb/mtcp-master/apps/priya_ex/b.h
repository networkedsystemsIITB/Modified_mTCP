#ifndef B_H
#define B_H
extern string mme_ip;
extern int mme_port;
void handle_ue(int conn_id, int id, void* request, char* packet);
void handle_c_reply1(int conn_id, int id, void* request, char* packet);
void handle_ds_reply1(int conn_id, int id, void* request, char* packet);
#endif
