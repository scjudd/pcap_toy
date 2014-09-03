> "If you're gonna play with C, you may as well play with libpcap."
>
> — Someone credible

```bash
git clone git@github.com:scjudd/pcap_toy.git
cd pcap_toy
make && sudo ./pcap_test enp4s0f0 "port 80"
```

Obviously, substitute `enp4s0f0` with whatever interface you'd like to capture
on.
