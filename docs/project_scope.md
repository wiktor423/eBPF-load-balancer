# L4 eBPF Load Balancer 

### Scope 
The goal of the project is implementation of a simple load balancer working entirely in the kernel-space, enabling optimal UDP packet forwarding. The LB tracks time of each backend server's response and uses it as one of the metrics to properly balance the incoming traffic. 

The performance of the servers can be inspected from the level of LB using Prometheus. 
