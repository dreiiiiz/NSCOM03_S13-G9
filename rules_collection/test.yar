rule test_minimal {
  strings:
    $a = "hello"
  condition:
    $a
}