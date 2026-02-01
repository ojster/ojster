group "default" {
  targets = ["binary"]
}

target "binary" {
  target = "binary-scratch"
  context = "."
  dockerfile = "Dockerfile"
  pull = true
  output = ["./bin"]
}

target "test" {
  target = "test-scratch"
  context = "."
  dockerfile = "Dockerfile"
  pull = true
  output = ["./log"]
}
