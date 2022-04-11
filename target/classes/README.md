Advantages of Multithreaded Server:

Quick and Efficient: Multithreaded server could respond efficiently and 
quickly to the increasing client queries quickly.
Waiting time for users decreases: 
In a single-threaded server, other users had to wait until the running process gets completed but in multithreaded servers, all users can get a response at a single time so no user has to wait for other processes to finish.
Threads are independent of each other: There is no relation between any two threads. When a client is connected a new thread is generated every time.
The issue in one thread does not affect other threads: If any error occurs in any of the threads then no other thread is disturbed, all other processes keep running normally. In a single-threaded server, every other client had to wait if any problem occurs in the thread.