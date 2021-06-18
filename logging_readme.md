# Allocation logging.

The patch on this branch logs every allocation and deallocation and generates a json file with the name

ruby-objects.<pid>.log

the interesting functions are all in gc.c - particularly `rvargc_log_memsize_of2`

There's a Ruby script that does some basic processing, I was using this to check the validity of the data, but I don't think it's much use anymore. It's in `object_log_parse.rb`

## Generating the graphs

You can run this with Rscript.

```
Rscript object_data.r ruby-objects.224737.log
```

Theoretically you should be able to pass the ruby-object file to the rscript file directly and have it just work. But the output of Railsbench is pretty big and R runs out of memory. I've been doing course filtering with grep to pre-process the files sometime and then passing that output into R

* I've had to filter all strings to ones with size > 0. I don't know why there are so many strings of size 0.
* I've also filtered out anything over 100000 bytes. There are only 3 but they're throwing the results off.
