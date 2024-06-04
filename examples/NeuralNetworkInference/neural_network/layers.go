package neural_network

type Layer interface {
	Eval(in interface{}) interface{}
	OutputScale() uint64
	Verif(in interface{}) interface{}
}
