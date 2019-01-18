#include "lib.h"

string mme_ip = "169.254.9.33";
int mme_port = 5000;
struct mme_state{
//	char b[5];
//	int val1;
	char* req;
	void* dsreq;
        int val1;
	char b[5];

};
char* temp_data = "hello";
/*void handle_c_reply1(int conn_id, int id, void* request, char* packet){
                //cout.flush();
//                cout<<"Data from C "<< conn_id << "data is "<< packet<<endl;
		int server_id = get_data_local("",conn_id);  
		getData(server_id, id, server_id, "remote", handle_ds_reply1);
	//	cout<<"server d received"<<endl;
//		packet = server_id;
//		sendData(server_id, id, (char*)request, 5); //oct4
		
}*/

void handle_ds_reply1(int conn_id, int id, void* request, char* packet){
//               cout<<"Data from C "<< conn_id << "data is "<< (char*)request<<endl;
		//cout<<"ds_reply"<<conn_id<<endl;
		int a=5,i,key_id;
		for(i=1;i<200;i++){
                        a = a*i;
                }
		string connid = to_string(conn_id);
		mme_state *x = static_cast<mme_state*>(request);
	//	cout<<"request is "<<(char*)(x->req)<<endl;
		if(id==1){
                        key_id = 100000+conn_id;
                        //key_id = 5;
                }
                else if(id==2){
                        key_id = 200000+conn_id;
                        //key_id = 6;
                }
		else if(id==3){
                        key_id = 300000+conn_id;
                }
		else if(id==4){
                        key_id = 400000+conn_id;
                }
		else{
                        key_id = 500000+conn_id;
                }

		x->dsreq = getDSptr(key_id);   //no need can uncomment dec5 //uncomment dec15
		removeDSptr(key_id);		//no need can uncomment dec5  //uncomment dec15
//		cout<<"getdata is "<<packet<<endl;
		removeRefPtr(id, (void*)x->req);
		//freeReqCtxt(conn_id, 1);
		char* pkt = writePktmem(id);
		memcpy((void*)pkt,(void*)(x->b),3);
		//sendData(conn_id, id, (char*)x->b, 3);
		sendData(conn_id, id, pkt, 3);
//		cout<<"reply to a sent"<<endl;
		freeReqCtxt(conn_id, id, 1);
/*		if(id==1){
                        key_id = 100000+conn_id;
                        //key_id = 5;
                }
                else{
                     	key_id = 200000+conn_id;
                        //key_id = 6;
                }*/
		delData(conn_id, id, key_id, "local");//no need can uncomment dec5 //uncomment dec15 //TODO uncomment when local
//		sendData(conn_id, id, connid.c_str(), 5);
}

void handle_c_reply1(int conn_id, int id, void* request, char* packet){
                //cout.flush();
		int a=5,i,key_id;
//                cout<<"Data from C "<< conn_id << "data is "<< packet<<endl;
                int server_id = get_data_local(id, "",conn_id);
		for(i=1;i<1000;i++){  //earlier loop was 1000
                        a = a*i;
                }
		 mme_state *x = static_cast<mme_state*>(request);
		//char* x;
		//x = (char*)request; //nov24
		//cout<<"request in c reply"<<x<<endl;
		freeReqCtxt(conn_id, id, 1);
		if(id==1){
                        key_id = 100000+server_id;
			//key_id = 5;
		}
                else if(id==2){
                        key_id = 200000+server_id;
			//key_id = 6;
		}
		else if(id==3){
                        key_id = 300000+conn_id;
                }
		else if(id==4){
                        key_id = 400000+conn_id;
                }
		else{
                        key_id = 500000+conn_id;
                }
		removeRefPtr(id, (void*)x->req);
                //freeReqCtxt(conn_id, 1);
                char* pkt = writePktmem(id);
                memcpy((void*)pkt,(void*)(x->b),3);
                //sendData(conn_id, id, (char*)x->b, 3);
                sendData(server_id, id, pkt, 3);
		freeReqCtxt(server_id, id, 1);
		//cout<<"reached here creply"<<endl;
                //getData(server_id, id, key_id, "local", handle_ds_reply1);
                //getData(server_id, id, server_id, "remote", handle_ds_reply1);
        //      cout<<"server d received"<<endl;
//              packet = server_id;
//              sendData(server_id, id, (char*)request, 5); //oct4

}

void handle_ue(int conn_id, int id, void* request, char* packet){
		//cout.flush();
		int a=conn_id,i, key_id, c_id;
		request = allocReqCtxt(conn_id, id, 1);
//		cout<<"conn id is "<< conn_id << "data is "<< packet<<endl;
		 c_id = createClient(id, "169.254.9.33", "169.254.9.78", 6000, "tcp");  //sep20
/*		if(id==0){
			c_id = createClient(id, "169.254.9.33", "169.254.9.78", 6000, "tcp");  //sep20
		}
		else if(id==1){
			c_id = createClient(id, "169.254.9.33", "169.254.9.78", 6001, "tcp");
		}
		else{
			c_id = createClient(id, "169.254.9.33", "169.254.9.78", 6002, "tcp");
		}
*/ //for multiple C
//		int c_id = createClient(id, "", "169.254.9.18", 7000, "tcp");
	//	cout<<"connected to C in B "<< c_id << endl;
		//char* data = request;
		//200000000 28
		for(i=1;i<20000000;i++){  //till 4core: 20000000 //20000000 //2000000
                        a = a+i;
                }
		
		//cout<<"address in handle "<<request<<endl;
		mme_state *x = static_cast<mme_state*>(request); 
		x->val1 = a;
		//char* y = new char[5];
		//y = "abcd";
       		//x->b = 'a';
//		x->req = temp_data;
		x->b[0]='a';
		x->b[1]='b';
		x->b[2]='\0';
		x->req = (char*)getRefPtr(id, (void*)packet);
		//memcpy((void*)(x->req),(void*)y, 5);
		//cout<<"request is "<<(char*)(x->req)<<endl;
		//char* x;
		
		//x = (char*)request;
		//x = static_cast<char*>(request);  //nov24
/*		x->req[0] = 'a';
    		x->req[1] = 'b';
		x->req[2] = 'c';
		x->req[3] = 'd';
		x->req[4] = '\0';*/ //seg fault here nov24
		//x[5] = 'f';
		//x[6] = 'g';
		//x[7] = '\0';
		//cout<<"request in handle_ue"<<x->b<<endl;
//		sendData(conn_id, id, data, 5);  //uncomment this for C
		addReqCtxt(c_id, id, request); //sep20
		registerCallback(c_id, id, "read", handle_c_reply1); //sep20
		
//		registerCallback(conn_id, "read", handle_ds_reply1);   //sep20  //sep25 //oct4
//		addReqCtxt(c_id, request); //sep20
		set_data_local(id, "",c_id,conn_id); //sep20
//		sendData(c_id, id, (char*)request, 5);  //uncomment this for C sep20
		
		//getData(conn_id, id, 5, "remote", handle_ds_reply1);
		//sleep(1);
		if(id==1){
			key_id = 100000+conn_id;
			//key_id = 5;
		}
		else if(id==2){
			key_id = 200000+conn_id;
			//key_id = 6;
		}
		else if(id==3){
			key_id = 300000+conn_id;
		}
		else if(id==4){
			key_id = 400000+conn_id;
		}
		else{
                        key_id = 500000+conn_id;
                }

//		setData(conn_id, id, key_id, "local", "abcd"); //sep21
//		getData(conn_id, id, conn_id, "remote", handle_ds_reply1);
		 //sendData(c_id, id, (char*)request, 5);		//oct5  //nov24
		char* pkt = writePktmem(id);
		memcpy((void*)pkt, (void*)(x->b), 3);
		 sendData(c_id, id, pkt, 3);		//oct5
//removeRefPtr(id, (void*)x->req);
//freeReqCtxt(conn_id, id, 1);
		//cout<<"reached here"<<endl;
		//getData(conn_id, id, conn_id);		//sep21
	//	removeRefPtr((void*)x->req);
}
/*
void handle_c_reply(int conn_id, int id, void* request, string packet){
		cout.flush();
		cout<<"Data from C "<< conn_id << "data is "<< packet<<endl;
}*/
int main(int argc, char *argv[]) {
	//check_usage(argc);
	int serverID = createServer("",mme_ip,mme_port, "tcp");
	registerCallback(serverID, -1, "read", handle_ue);
	int reqpool[1] = {sizeof(struct mme_state)};
	initRequest(reqpool, 1);
	//initRequest(8);
	startEventLoop();
	return 0;
}
