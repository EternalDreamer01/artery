
<script setup>
// This starter template is using Vue 3 <script setup> SFCs
// Check out https://vuejs.org/api/sfc-script-setup.html#script-setup
import Compile from "./compile.vue";
import Config from "./config.vue";
import project_config from "./project_config.vue";
import { ref } from "vue";
import * as Vue from 'vue';

const project_loaded = ref(Vue.inject("$project_loaded"))



</script>

<template>
  <Suspense>
    <template #default>
        <project_config/>
      </template>
      <template #fallback>
        <div>Loading Profile...</div>
      </template>
  </Suspense>
    <h4 id="artery_path"> Project name: {{ project_loaded==undefined ? "no project selected" : project_loaded.project_name }} </h4>
  <Config></Config>
  <Compile></Compile>
</template>
