if (!requireNamespace('tidyverse'))
  install.packages('tidyverse')
if (!requireNamespace('ggplot2'))
  install.packages('ggplot2')

library(ggplot2)
library(tidyverse)
library(readr)
library(jsonlite)
library(stringr)
library(dplyr)

setwd("~/src/ruby")
rm(list = ls())

# load the json objects from the file. We need to comma seperate them and wrap
# them in an array for jsonlite to be able to turn them into a data frame.
object_json <- fromJSON(
  paste('[', paste(
    read_lines("ruby-objects.187089.log"), 
    collapse = ","), ']'))

# histogram of all string allocations
strings <- object_json %>% 
  filter(rtype == "T_STRING") %>%
  filter(state == "alloc")

ggplot(strings, aes(x = size)) +
  geom_histogram(binwidth = 1)





