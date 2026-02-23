group "default" {
  targets = ["image"]
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

target "image" {
  target = "binary-scratch"
  context = "."
  dockerfile = "Dockerfile"
  pull = true
  output = ["type=image,name=ojster/ojster:latest,load=true"]
}
