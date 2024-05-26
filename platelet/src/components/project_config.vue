<script setup>
import { app } from "@tauri-apps/api";
import { invoke } from "@tauri-apps/api/tauri";
import { ref } from "vue";
import * as Vue from 'vue';

Vue.provide("$project_loaded", await invoke("get_loaded_project",).catch((error) => console.log(error)));

</script>

<template></template>