<script setup>
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/tauri";


async function compile_artery() {
  // Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
  await invoke("compile_artery").catch((error) => console.error(error));
}


async function build_config() {
  await invoke("build_config", ).catch((error) => console.error(error));
}
</script>

<template>
  <button @click="compile_artery"> Compile Artery </button>
  <button @click="build_config"> Build Config </button>

</template>
