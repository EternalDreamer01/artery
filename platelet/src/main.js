import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import "./styles.css";
import App from "./App.vue";
import HomePage from "./components/homepage.vue";
import NewProject from "./components/new_project.vue"
import config from "./components/config.vue";
import compile from "./components/compile.vue";


const router = createRouter({
    history: createWebHistory(),
    routes: [
            {path: '/', name: 'Home', component: HomePage},
            {path: '/newproject', name: 'NewProject', component: NewProject}
    ]
})

createApp(App).use(router).mount("#app");
