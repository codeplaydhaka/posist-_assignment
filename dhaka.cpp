#include<bits/stdc++.h>
using namespace std;
#define pb push_back
typedef struct node
{
    string name,address,mobileno;
    int nodenumber;
    int nodeid;

}node;
node arr[1000003];
int visited[1000003];
vector<int> v[100002];
int key;
set<string> s;
int ans=0;
int dfs(int root)
{

    int i;

    visited[root]=1;
    int maxi=0;
    for(i=0;i<v[root].size();i++)
    {
        if(visited[v[root][i]]==0)
        {
            visited[v[root][i]]=1;
            int x=dfs(v[root][i]);
            maxi=max(maxi,x);
        }

    }
     return 1+maxi;


}
string encryption(string x)
{
    if(s.find(x)!=s.end())
    {
        return x;
    }
    for(int i=0;i<x.size();i++)
    {
        x[i]=(x[i]+key);
    }
    s.insert(x);
    return x;
}
string decryption(string x)
{
    for(int i=0;i<x.size();i++)
    {
        x[i]=(x[i]-key);
    }
    return x;
}
int cnt=1;
int parent[100002];
int id[1000002];
int nodenumber[100002];
int iscreated[1000003];
void fun1()
{
    cout<<"enter node id"<<endl;
    cin>>id[cnt];
    if(iscreated[id[cnt]]==1)
    {
        cout<<"node is already been created"<<endl;
        return ;
    }
    iscreated[id[cnt]]=1;
    parent[id[cnt]]=-1;
    cnt++;
    string x;
    cout<<"enter owner name"<<endl;
    cin>>x;
    arr[id[cnt-1]].name=x;
    x=encryption(x);
    string y;
    cout<<"enter owner address"<<endl;
    cin>>y;
    arr[id[cnt-1]].address=y;
    y=encryption(y);
    string z;
    cout<<"enter owner mobile no."<<endl;
    cin>>z;
    arr[id[cnt-1]].mobileno=z;
    z=encryption(z);
}
void fun2()
{

}
void fun3()
{
     cout<<"enter node id"<<endl;
    cin>>id[cnt];
    if(iscreated[id[cnt]]==1)
    {
        cout<<"node is already been created"<<endl;
        return ;
    }
    iscreated[id[cnt]]=1;
    parent[id[cnt]]=-1;
    cnt++;
    string x1;
    cout<<"enter owner name"<<endl;
    cin>>x1;
    arr[id[cnt-1]].name=x1;
   x1=encryption(x1);
    string y;
    cout<<"enter owner address"<<endl;
    cin>>y;
    arr[id[cnt-1]].address=y;
    y=encryption(y);
    string z;
    cout<<"enter owner mobile no."<<endl;
    cin>>z;
    arr[id[cnt-1]].mobileno=z;


    int opt;
    cout<<"enter 1 if u want this node to parent else enter 2"<<endl;
    cin>>opt;
    int x;
    cout<<"enter id of node to which u want to connect"<<endl;
    cin>>x;
    if(iscreated[x]==0)
    {
        cout<<"this node havent been created"<<endl;
        return ;
    }
    if(opt==1)
    {
        v[id[cnt-1]].pb(x);
        parent[x]=id[cnt-1];
    }
    else
    {
       v[x].pb(id[cnt-1]);
       parent[id[cnt-1]]=x;
    }
}
void fun4()
{
    cout<<"enter key"<<endl;
    int f;

    cin>>f;
    key=f;
    for(int i=1;i<cnt;i++)
    {
        arr[id[cnt]].name=encryption(arr[id[cnt]].name);
        arr[id[cnt]].address=encryption(arr[id[cnt]].name);
        arr[id[cnt]].mobileno=encryption(arr[id[cnt]].name);
    }
}
void fun5()
{
    cout<<"enter node id"<<endl;
    int x;
    cin>>x;

    int k;
    string name;
    cout<<"enter owner name and key"<<endl;
    cin>>name>>k;
    if(k==key&&(decryption(arr[x].name)==name))
    {
        cout<<"u r verified"<<endl;
    }
    else
    {
        cout<<"fake"<<endl;
    }

}
void fun6()
{

}
void fun7()
{
    int i;
    cout<<"enter id"<<endl;
    cin>>i;

    string x;
    cout<<"enter owner name"<<endl;
    cin>>x;
    arr[i].name=x;
   x=encryption(x);
    string y;
    cout<<"enter owner address"<<endl;
    cin>>y;
    arr[i].address=y;
    y=encryption(y);
    string z;
    cout<<"enter owner mobile no."<<endl;
    cin>>z;
    arr[i].mobileno=z;
}
void fun8()
{
    int x;
    cout<<"enter node id from which u want to maximum length"<<endl;
    cin>>x;

    cout<<dfs(x)<<endl;
    memset(visited,0,sizeof(visited));

}
void fun9()
{
    int x;
    cout<<"enter node id from which u want maximum length from sub node"<<endl;
    cin>>x;
    if(v[x].size()!=0)
    cout<<dfs(x)-1<<endl;
    else
        cout<<"0"<<endl;

        memset(visited,0,sizeof(visited));


}
void fun10()
{
    int a, b;
    cout<<"enter id of parent node after merging"<<endl;
    cin>>a;
    cout<<"enter id of child node after merging"<<endl;
    cin>>b;
    parent[b]=a;
    v[a].push_back(b);

}

int main()
{

    int option;
    cin>>option;
    switch(option)
    {
        case 1: fun1();
        break;
        case 2: fun2();
        break;
        case 3: fun3();
        break;
        case 4: fun4();
        break;
        case 5: fun5();
        break;
        case 6: fun6();
        break;
        case 7: fun7();
        break;
        case 8: fun8();
        break;
        case 9: fun9();
        break;
        case 10: fun10();
        break;
    }

}
