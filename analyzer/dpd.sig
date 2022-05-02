signature dpd_genisys_message {
  ip-proto == tcp
  payload /^[\xf1-\xfe]/
  enable "spicy_Genisys_TCP"
}
