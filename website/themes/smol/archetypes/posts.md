---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
slug: {{ now.Format "2006-01-02" }}-{{ .Name | urlize }}
type: posts
draft: true
katex: false
summary: 'This is test summary'
categories:
  - default
tags:
  - default
---

{{< toc >}}