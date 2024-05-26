<script setup>
import { ref } from "vue";
import { invoke } from "@tauri-apps/api/tauri";
import { open } from '@tauri-apps/api/dialog'
async function pick_file() {
  // Open a dialog
  const file = await open({
    multiple: false,
    directory: false,
    filters: [{
    name: 'osm',
    extensions: ['osm']
  }]
  });
  if (file) {
    osm_path.value = file;
  }
}

const osm_path = ref("");

</script>

<template>
  <div id="scenario_configuration">
  <h5> Scenario configuration </h5>
  <button type="button" @click="pick_file"> pick osm map file </button>
            <p> {{ osm_path }} </p>
  <p>trips number:</p>
  <input id="trips_number" type="text" inputmode="numeric"/>
</div>
</template>


