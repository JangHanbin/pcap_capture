#include <iostream>
#include <pcap.h>
#include <iomanip>

using namespace std;


void printLine()
{
    cout<<"-----------------------------------------------"<<endl;
}

void printByHexData(u_int8_t *printArr, int length)
{

    for(int i=0;i<length;i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";

    }

    cout<<dec<<endl;
    printLine();
}


int main(int argc, char* argv[])
{

    char* device = argv[1];
    cout<<device<<endl;
    char errbuf[PCAP_BUF_SIZE];
    pcap_t* pcd =  pcap_open_live(device, BUFSIZ,1, 200,errbuf);

    struct pcap_pkthdr *hdr;
    const u_char* pkt_data;

    int value_of_next_ex;

      while(true)
      {
          value_of_next_ex = pcap_next_ex(pcd,&hdr,&pkt_data);

          switch (value_of_next_ex)
          {
              case 1:
                  //do something with pkt_data and hdr

                  printByHexData((uint8_t*)pkt_data, hdr->len);
                  break;
              case 0:
                  cout<<"need a sec.. to packet capture"<<endl;
                  continue;
              case -1:
                  perror("pcap_next_ex function has an error!!!");
                  exit(1);
              case -2:
                  cout<<"the packet have reached EOF!!"<<endl;
                  exit(0);
              default:
                  break;
          }


      }

    return 0;
}
