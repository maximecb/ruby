r <- getOption("repos")
r["CRAN"] <- "https://www.stats.bris.ac.uk/R/"
options(repos = r)

if(!require("ggplot2")){
  install.packages("ggplot2")
}
if(!require("tidyverse")) {
  install.packages('tidyverse')
}
library(ggplot2)
library(readr)
library(jsonlite)
library(stringr)
library(dplyr)

log_file = commandArgs(TRUE)

log_file = "~/src/railsbench/strings.log"

# load the json objects from the file. We need to comma seperate them and wrap
# them in an array for jsonlite to be able to turn them into a data frame.
object_json <- fromJSON(paste('[', paste(read_lines(log_file), collapse = ","), ']'))

# histogram of all string allocations for strings less than 500 bytes, including 0 bytes strings
strings <- object_json %>% 
  filter(rtype == "T_STRING") %>%
  filter(state == "alloc") %>% 
  filter(size < 500) %>%
  filter(size > 0)

ggplot(strings, aes(x = size)) +
  geom_histogram(binwidth = 4)
 
# histogram of all string allocations for strings less than 500 bytes, 
# including 0 bytes strings
strings <- object_json %>% 
  filter(rtype == "T_STRING") %>%
  filter(state == "alloc") %>% 
  filter(size > 1000)

ggplot(strings, aes(x = size)) +
  geom_histogram(binwidth = 4)
