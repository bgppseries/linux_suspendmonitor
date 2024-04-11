#include <cinttypes>
#include <numeric>
#include <set>
#include <string>
#include <string.h>
#include <tuple>
#include <vector>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include "RingBuffer.h"
#include "SuspendInfo.h"

using namespace std;

pthread_mutex_t data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  fifo_nonzero;
static volatile int64_t isEmpty = 0;
static volatile int64_t fifo_size = 0;

class SuspendMonitorDevice {
public:
    SuspendMonitorDevice(char* name){
        mDev_name = name;
    }
    ~SuspendMonitorDevice(){
        epoll_ctl(mEpollfd, EPOLL_CTL_DEL, mFd, &mEpev);
        close(mEpollfd);
        close(mFd);
    }

    int InitSetup(){
        //open "/proc/suspend_monitor"
        mFd = open(mDev_name, O_RDWR); 
        if (mFd == -1) {
			printf("open %s fail, Check!!!\n",mDev_name);
            return errno;
        }
        //epoll
        mEpollfd = epoll_create(MAX_EPOLL_EVENTS);
        if (mEpollfd == -1) {
			printf("epoll_create failed errno = %d ", errno);	
            return errno;
        }
		printf("epoll_create ok epollfd= %d \n", mEpollfd);
		
        //add fd for epoll
        memset(&mEpev, 0, sizeof(mEpev));
	    mEpev.data.fd = mFd;
	    mEpev.events = EPOLLIN;
        if (epoll_ctl(mEpollfd, EPOLL_CTL_ADD, mFd, &mEpev) < 0) {
			printf("epoll_ctl failed, errno = %d \n", errno);
            return errno;
        }  
        return 0;
    }
 
    int getFd() { return mFd; };
    int getepollfd() { return mEpollfd; };
    char* getBuffer() { return mBuf; };

    SuspendMonitorInfo& GetFristDataInfo(){
        return mRingBuffer.Get(0);
    }
    void PPopFrontDatainfo(){
        mRingBuffer.PopFront();
    }

    void PopBackDatainfo(){
        mRingBuffer.PopBack();
    }

    SuspendMonitorInfo& GetBackDataInfo(){
        return mRingBuffer.Back();
    }

    void AppendDatainfo(SuspendMonitorInfo& info){
        mRingBuffer.Append(info);
    }

    size_t GetFifoSize(){
        return mRingBuffer.GetSize();
    }

    void FifoReset(size_t capacity) {
        mRingBuffer.Reset(capacity);
    }

    bool FifoIsEmpty() { 
        return mRingBuffer.IsEmpty();
    }

private:
    int mFd; //"/proc/suspend_monitor"
    int mEpollfd;
    struct epoll_event mEpev;
    char *mDev_name;
    char mBuf[50];
    RingBuffer<SuspendMonitorInfo> mRingBuffer;
};

static void * DoSuspendMonitor(void *arg){
        int ret;
        //static int index = 0;
        ssize_t leng = 0, i = 0;
        struct epoll_event epev;
        SuspendMonitorInfo deviceinfo;
        SuspendMonitorDevice* device = (SuspendMonitorDevice*)arg;
        char* buf = device->getBuffer();
        device->FifoReset(BUFFER_SIZE);

        while(1){
            printf("suspend_monitor epoll_wait... \n");
            ret = epoll_wait(device->getepollfd(), &epev, MAX_EPOLL_EVENTS, -1);
            if (ret == -1 && errno != EINTR) {
				printf("suspend_monitor epoll_wait failed; errno=%d\n", errno);
                return (void*)-1;
            }
            leng  = read(device->getFd(), buf, KERNEL_DATA_LENG); //MAX 32 Byte
            if (leng == KERNEL_DATA_LENG){
                //8 bute kernel time
                for (i = 0; i < 8; i++){
                    deviceinfo.info.kernel_time[i] = buf[i];
                    printf("kernel_time[%d] = 0x%x \n", i, deviceinfo.info.kernel_time[i]);
                }      
                //16 byte UTC
                 for (i = 0; i < 16; i++){
                    deviceinfo.info.utc_time[i] =  buf[i+8];
                    printf("utc_time[%d] = 0x%x \n", i, deviceinfo.info.utc_time[i]);
                }
                //4 byte status_old
                for (i = 0; i < 4; i++){
                    deviceinfo.info.status_old[i] = buf[i+24];
                    printf("status_old[%d] = %d \n", i, deviceinfo.info.status_old[i]);
                }
                //4byte status_new
                for (i = 0; i < 4; i++){
                    deviceinfo.info.status_new[i] = buf[i+28];
                    printf("status_new[%d] = %d \n", i, deviceinfo.info.status_new[i]);
                }

                ret = pthread_mutex_lock(&data_mutex); //get lock
		        if (ret != 0) {
			        printf("Error on pthread_mutex_lock(), ret = %d\n", ret);
			        return (void *)-1;
		        }

                //save 
                device->AppendDatainfo(deviceinfo);
                fifo_size = device->GetFifoSize();
                
                ret = pthread_mutex_unlock(&data_mutex); //unlock
		        if (ret != 0) {
			        printf("Error on pthread_mutex_unlock(), ret = %d\n", ret);
			        return (void *)-1;
		        }

                if (isEmpty){
                    for (i = 0; i < isEmpty; i++)
                        pthread_cond_signal(&fifo_nonzero);
                }
                printf("Current BufferSize = %ld \n", fifo_size);
            }

        }
}

int main(){
    int ret; 
    pthread_t ptd;
    //check device
    SuspendMonitorDevice* monitorDevice = new SuspendMonitorDevice((char*)DEV_NAME);
    if ( monitorDevice->InitSetup() != 0){
		printf("SuspendMonitorDevice::InitSetup fail \n");
        return -1;
    }
	printf("SuspendMonitorDevice::InitSetup OK \n");
    
    /*
    ret = pthread_create(&ptd, NULL, DoSuspendMonitor, (void*)monitorDevice);
    if (ret) {
		printf("DoSuspendMonitor pthread_create failed; errno=%d", errno);
		return -1;
    }
    */
    DoSuspendMonitor((void*)monitorDevice);

    pthread_mutex_destroy(&data_mutex);
    //not call here
    return 0;
}