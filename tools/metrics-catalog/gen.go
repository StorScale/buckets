// SPDX-License-Identifier: AGPL-3.0-or-later

// Generates a test file, to be overlaid onto minio/cmd, that prints the
// metrics MinIO defines: v2 descriptions reachable from each endpoint's
// metric groups (from init() in metrics-v2.go), v3 descriptors of every
// collector path, and the names built at run time (ILM actions, batch jobs).
// See run.sh.
//
//	go run gen.go <minio>/cmd <out.go>
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var fset = token.NewFileSet()
var funcs = map[string]*ast.FuncDecl{}
var mdFuncs = map[string]bool{}

func src(n ast.Node) string {
	var b bytes.Buffer
	printer.Fprint(&b, fset, n)
	return strings.Join(strings.Fields(b.String()), " ")
}

func returnsMD(f *ast.FuncDecl) bool {
	if f.Type.Results == nil || len(f.Type.Results.List) != 1 {
		return false
	}
	id, ok := f.Type.Results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "MetricDescription"
}

// collect walks fn (and package funcs it calls) for MD expressions.
func collect(name string, seen map[string]bool, out map[string]bool) {
	if seen[name] {
		return
	}
	seen[name] = true
	f := funcs[name]
	if f == nil || f.Body == nil {
		return
	}
	ast.Inspect(f.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok {
				if mdFuncs[id.Name] {
					out[src(x)] = true
					return false
				}
				if funcs[id.Name] != nil {
					collect(id.Name, seen, out)
				}
			}
		case *ast.CompositeLit:
			if id, ok := x.Type.(*ast.Ident); ok && id.Name == "MetricDescription" {
				out[src(x)] = true
				return false
			}
		}
		return true
	})
}

func main() {
	dir := os.Args[1]
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, fn := range files {
		if strings.HasSuffix(fn, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, fn, nil, 0)
		if err != nil {
			panic(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				funcs[fd.Name.Name] = fd
				if returnsMD(fd) {
					mdFuncs[fd.Name.Name] = true
				}
			}
		}
	}
	// endpoint -> group constructors, from metrics-v2.go init()
	var initFn *ast.FuncDecl
	for _, fn := range files {
		if filepath.Base(fn) != "metrics-v2.go" {
			continue
		}
		f, _ := parser.ParseFile(fset, fn, nil, 0)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "init" {
				initFn = fd
			}
		}
	}
	lists := map[string][]string{}
	ast.Inspect(initFn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 {
			return true
		}
		lhs := src(as.Lhs[0])
		cl, ok := as.Rhs[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range cl.Elts {
			if c, ok := e.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok {
					lists[lhs] = append(lists[lhs], id.Name)
				}
			}
		}
		return true
	})
	endpoints := map[string][]string{
		"cluster": append(append([]string{}, lists["clusterMetricsGroups"]...), lists["peerMetricsGroups"]...),
		"node":    lists["nodeGroups"],
		"bucket":  lists["bucketMetricsGroups"],
	}
	var b strings.Builder
	b.WriteString("package cmd\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n\t\"testing\"\n\t\"github.com/prometheus/client_golang/prometheus\"\n\tmadmin \"github.com/minio/madmin-go/v3\"\n\t\"github.com/minio/minio/internal/bucket/lifecycle\"\n)\n\nfunc TestDumpMetricCatalog(t *testing.T) {\n\tpr := func(ep string, d MetricDescription) { fmt.Printf(\"V2\\t%s\\t%s\\t%s\\t%q\\n\", ep, prometheus.BuildFQName(string(d.Namespace), string(d.Subsystem), string(d.Name)), d.Type, d.Help) }\n")
	eps := []string{"bucket", "cluster", "node"}
	for _, ep := range eps {
		exprs := map[string]bool{}
		for _, g := range endpoints[ep] {
			collect(g, map[string]bool{}, exprs)
		}
		keys := make([]string, 0, len(exprs))
		for k := range exprs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "\tpr(%q, %s) // EXPR\n", ep, k)
		}
	}
	// names built at run time
	b.WriteString("\tfor i := range globalScannerMetrics.actions { pr(\"cluster\", MetricDescription{Namespace: nodeMetricNamespace, Subsystem: ilmSubsystem, Name: MetricName(\"action_count_\" + toSnake(lifecycle.Action(i).String())), Help: \"Total action outcome of lifecycle checks since server uptime\", Type: counterMetric}) }\n")
	b.WriteString("\tfor _, jt := range madmin.SupportedJobTypes { j := toSnake(string(jt)); pr(\"cluster\", MetricDescription{Namespace: bucketMetricNamespace, Subsystem: \"batch\", Name: MetricName(j + \"_objects\"), Help: \"Get successfully completed batch job \" + j + \"objects\", Type: counterMetric}); pr(\"cluster\", MetricDescription{Namespace: bucketMetricNamespace, Subsystem: \"batch\", Name: MetricName(j + \"_objects_failed\"), Help: \"Get failed batch job \" + j + \"objects\", Type: counterMetric}) }\n")
	b.WriteString("\tc := newMetricGroups(prometheus.NewRegistry())\n\tfor p, g := range c.mgMap { for _, d := range g.Descriptors { fmt.Printf(\"V3\\t%s\\t%s_%s\\t%s\\t%q\\t%s\\n\", p, p.metricPrefix(), d.Name, d.Type, d.Help, strings.Join(d.VariableLabels, \",\")) } }\n\tfor p, g := range c.bucketMGMap { for _, d := range g.Descriptors { fmt.Printf(\"V3\\t%s\\t%s_%s\\t%s\\t%q\\t%s\\n\", p, p.metricPrefix(), d.Name, d.Type, d.Help, strings.Join(d.VariableLabels, \",\")) } }\n}\n")
	os.WriteFile(os.Args[2], []byte(b.String()), 0o644)
}
